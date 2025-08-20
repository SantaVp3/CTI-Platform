package services

import (
	"fmt"
	"strconv"
	"strings"

	"cti-platform/internal/models"
	"gorm.io/gorm"
)

type ActivityService struct {
	db *gorm.DB
}

func NewActivityService(db *gorm.DB) *ActivityService {
	return &ActivityService{db: db}
}

// ActivityListParams represents parameters for listing activities
type ActivityListParams struct {
	Page            int    `json:"page"`
	Limit           int    `json:"limit"`
	Name            string `json:"name"`
	ActivityType    string `json:"activity_type"`
	Phase           string `json:"phase"`
	Status          string `json:"status"`
	Severity        string `json:"severity"`
	CampaignID      string `json:"campaign_id"`
	ThreatActorID   string `json:"threat_actor_id"`
	StartTimeFrom   string `json:"start_time_from"`
	StartTimeTo     string `json:"start_time_to"`
	Location        string `json:"location"`
	Source          string `json:"source"`
}

// ActivityResponse represents the response structure for activity lists
type ActivityResponse struct {
	Data  []models.Activity `json:"data"`
	Total int64             `json:"total"`
	Page  int               `json:"page"`
	Limit int               `json:"limit"`
}

// GetActivities retrieves activities with filtering and pagination
func (s *ActivityService) GetActivities(params ActivityListParams) (*ActivityResponse, error) {
	var activities []models.Activity
	var total int64

	// Build query with filters
	query := s.db.Model(&models.Activity{})

	// Apply filters
	if params.Name != "" {
		query = query.Where("name LIKE ?", "%"+params.Name+"%")
	}
	if params.ActivityType != "" {
		query = query.Where("activity_type = ?", params.ActivityType)
	}
	if params.Phase != "" {
		query = query.Where("phase = ?", params.Phase)
	}
	if params.Status != "" {
		query = query.Where("status = ?", params.Status)
	}
	if params.Severity != "" {
		query = query.Where("severity = ?", params.Severity)
	}
	if params.CampaignID != "" {
		if campaignID, err := strconv.ParseUint(params.CampaignID, 10, 64); err == nil {
			query = query.Where("campaign_id = ?", campaignID)
		}
	}
	if params.ThreatActorID != "" {
		if actorID, err := strconv.ParseUint(params.ThreatActorID, 10, 64); err == nil {
			query = query.Where("threat_actor_id = ?", actorID)
		}
	}
	if params.StartTimeFrom != "" {
		query = query.Where("start_time >= ?", params.StartTimeFrom)
	}
	if params.StartTimeTo != "" {
		query = query.Where("start_time <= ?", params.StartTimeTo)
	}
	if params.Location != "" {
		query = query.Where("location LIKE ?", "%"+params.Location+"%")
	}
	if params.Source != "" {
		query = query.Where("source LIKE ?", "%"+params.Source+"%")
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count activities: %w", err)
	}

	// Apply pagination
	offset := (params.Page - 1) * params.Limit
	query = query.Offset(offset).Limit(params.Limit)

	// Order by created_at desc
	query = query.Order("created_at DESC")

	// Preload relationships
	query = query.Preload("Campaign").Preload("ThreatActor").Preload("Creator").Preload("ActivityIOCs.IOC")

	// Execute query
	if err := query.Find(&activities).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch activities: %w", err)
	}

	return &ActivityResponse{
		Data:  activities,
		Total: total,
		Page:  params.Page,
		Limit: params.Limit,
	}, nil
}

// GetActivityByID retrieves a single activity by ID
func (s *ActivityService) GetActivityByID(id uint) (*models.Activity, error) {
	var activity models.Activity
	
	if err := s.db.Preload("Campaign").Preload("ThreatActor").Preload("Creator").
		Preload("ActivityIOCs.IOC.Type").First(&activity, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("activity not found")
		}
		return nil, fmt.Errorf("failed to fetch activity: %w", err)
	}

	return &activity, nil
}

// CreateActivity creates a new activity
func (s *ActivityService) CreateActivity(activity *models.Activity) error {
	if err := s.validateActivity(activity); err != nil {
		return err
	}

	if err := s.db.Create(activity).Error; err != nil {
		return fmt.Errorf("failed to create activity: %w", err)
	}

	// Reload with relationships
	return s.db.Preload("Campaign").Preload("ThreatActor").Preload("Creator").
		First(activity, activity.ID).Error
}

// UpdateActivity updates an existing activity
func (s *ActivityService) UpdateActivity(id uint, updates *models.Activity) (*models.Activity, error) {
	var activity models.Activity
	
	// Check if activity exists
	if err := s.db.First(&activity, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("activity not found")
		}
		return nil, fmt.Errorf("failed to fetch activity: %w", err)
	}

	if err := s.validateActivity(updates); err != nil {
		return nil, err
	}

	// Update the activity
	if err := s.db.Model(&activity).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("failed to update activity: %w", err)
	}

	// Reload with relationships
	if err := s.db.Preload("Campaign").Preload("ThreatActor").Preload("Creator").
		First(&activity, id).Error; err != nil {
		return nil, fmt.Errorf("failed to reload activity: %w", err)
	}

	return &activity, nil
}

// DeleteActivity deletes an activity
func (s *ActivityService) DeleteActivity(id uint) error {
	var activity models.Activity
	
	// Check if activity exists
	if err := s.db.First(&activity, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("activity not found")
		}
		return fmt.Errorf("failed to fetch activity: %w", err)
	}

	// Delete the activity (cascade will handle related records)
	if err := s.db.Delete(&activity).Error; err != nil {
		return fmt.Errorf("failed to delete activity: %w", err)
	}

	return nil
}

// GetActivityTimeline retrieves activities in timeline format
func (s *ActivityService) GetActivityTimeline(params ActivityListParams) (*ActivityResponse, error) {
	var activities []models.Activity
	var total int64

	// Build query with filters (similar to GetActivities but ordered by start_time)
	query := s.db.Model(&models.Activity{})

	// Apply same filters as GetActivities
	if params.CampaignID != "" {
		if campaignID, err := strconv.ParseUint(params.CampaignID, 10, 64); err == nil {
			query = query.Where("campaign_id = ?", campaignID)
		}
	}
	if params.ThreatActorID != "" {
		if actorID, err := strconv.ParseUint(params.ThreatActorID, 10, 64); err == nil {
			query = query.Where("threat_actor_id = ?", actorID)
		}
	}
	if params.StartTimeFrom != "" {
		query = query.Where("start_time >= ?", params.StartTimeFrom)
	}
	if params.StartTimeTo != "" {
		query = query.Where("start_time <= ?", params.StartTimeTo)
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count timeline activities: %w", err)
	}

	// Apply pagination
	offset := (params.Page - 1) * params.Limit
	query = query.Offset(offset).Limit(params.Limit)

	// Order by start_time for timeline view
	query = query.Order("start_time ASC, created_at ASC")

	// Preload relationships
	query = query.Preload("Campaign").Preload("ThreatActor").Preload("Creator")

	// Execute query
	if err := query.Find(&activities).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch timeline activities: %w", err)
	}

	return &ActivityResponse{
		Data:  activities,
		Total: total,
		Page:  params.Page,
		Limit: params.Limit,
	}, nil
}

// validateActivity validates activity data
func (s *ActivityService) validateActivity(activity *models.Activity) error {
	if strings.TrimSpace(activity.Name) == "" {
		return fmt.Errorf("activity name is required")
	}

	if activity.ConfidenceLevel < 0 || activity.ConfidenceLevel > 100 {
		return fmt.Errorf("confidence level must be between 0 and 100")
	}

	// Validate foreign key references if provided
	if activity.CampaignID != nil {
		var campaign models.Campaign
		if err := s.db.First(&campaign, *activity.CampaignID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fmt.Errorf("campaign not found")
			}
			return fmt.Errorf("failed to validate campaign: %w", err)
		}
	}

	if activity.ThreatActorID != nil {
		var actor models.ThreatActor
		if err := s.db.First(&actor, *activity.ThreatActorID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fmt.Errorf("threat actor not found")
			}
			return fmt.Errorf("failed to validate threat actor: %w", err)
		}
	}

	return nil
}
