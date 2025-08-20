package services

import (
	"errors"
	"fmt"
	"time"

	"cti-platform/internal/models"

	"gorm.io/gorm"
)

type CampaignService struct {
	db *gorm.DB
}

// Create campaign request structure
type CreateCampaignRequest struct {
	Name            string     `json:"name" binding:"required"`
	Description     string     `json:"description"`
	ThreatActorID   *uint      `json:"threat_actor_id"`
	StartDate       *time.Time `json:"start_date"`
	EndDate         *time.Time `json:"end_date"`
	ConfidenceLevel int        `json:"confidence_level"`
}

// Update campaign request structure
type UpdateCampaignRequest struct {
	Name            *string    `json:"name"`
	Description     *string    `json:"description"`
	ThreatActorID   *uint      `json:"threat_actor_id"`
	StartDate       *time.Time `json:"start_date"`
	EndDate         *time.Time `json:"end_date"`
	ConfidenceLevel *int       `json:"confidence_level"`
	IsActive        *bool      `json:"is_active"`
}

// Search campaign request structure
type CampaignSearchRequest struct {
	Name          string `form:"name"`
	ThreatActorID uint   `form:"threat_actor_id"`
	IsActive      *bool  `form:"is_active"`
	Page          int    `form:"page"`
	Limit         int    `form:"limit"`
}

func NewCampaignService(db *gorm.DB) *CampaignService {
	return &CampaignService{db: db}
}

// Create campaign
func (s *CampaignService) CreateCampaign(req CreateCampaignRequest, userID uint) (*models.Campaign, error) {
	// Check if campaign name already exists
	var existingCampaign models.Campaign
	err := s.db.Where("name = ?", req.Name).First(&existingCampaign).Error
	if err == nil {
		return nil, errors.New("campaign name already exists")
	}

	// If threat actor is specified, validate its existence
	if req.ThreatActorID != nil {
		var actor models.ThreatActor
		err = s.db.First(&actor, *req.ThreatActorID).Error
		if err != nil {
			return nil, errors.New("specified threat actor does not exist")
		}
	}

	// Set default values
	if req.ConfidenceLevel == 0 {
		req.ConfidenceLevel = 50
	}

	campaign := models.Campaign{
		Name:            req.Name,
		Description:     req.Description,
		ThreatActorID:   req.ThreatActorID,
		StartDate:       req.StartDate,
		EndDate:         req.EndDate,
		IsActive:        true,
		ConfidenceLevel: req.ConfidenceLevel,
		CreatedBy:       userID,
	}

	err = s.db.Create(&campaign).Error
	if err != nil {
		return nil, err
	}

	// 加载关联数据
	err = s.db.Preload("ThreatActor").Preload("Creator").Preload("IOCs").First(&campaign, campaign.ID).Error
	if err != nil {
		return nil, err
	}

	return &campaign, nil
}

// Get campaign details
func (s *CampaignService) GetCampaign(id uint) (*models.Campaign, error) {
	var campaign models.Campaign
	err := s.db.Preload("ThreatActor").Preload("Creator").Preload("IOCs").First(&campaign, id).Error
	if err != nil {
		return nil, err
	}
	return &campaign, nil
}

// Update campaign
func (s *CampaignService) UpdateCampaign(id uint, req UpdateCampaignRequest, userID uint) (*models.Campaign, error) {
	var campaign models.Campaign
	err := s.db.First(&campaign, id).Error
	if err != nil {
		return nil, err
	}

	// If updating name, check for duplicates
	if req.Name != nil && *req.Name != campaign.Name {
		var existingCampaign models.Campaign
		err = s.db.Where("name = ? AND id != ?", *req.Name, id).First(&existingCampaign).Error
		if err == nil {
			return nil, errors.New("campaign name already exists")
		}
		campaign.Name = *req.Name
	}

	// Update other fields
	if req.Description != nil {
		campaign.Description = *req.Description
	}
	if req.ThreatActorID != nil {
		// Validate threat actor existence
		var actor models.ThreatActor
		err = s.db.First(&actor, *req.ThreatActorID).Error
		if err != nil {
			return nil, errors.New("specified threat actor does not exist")
		}
		campaign.ThreatActorID = req.ThreatActorID
	}
	if req.StartDate != nil {
		campaign.StartDate = req.StartDate
	}
	if req.EndDate != nil {
		campaign.EndDate = req.EndDate
	}
	if req.ConfidenceLevel != nil {
		campaign.ConfidenceLevel = *req.ConfidenceLevel
	}
	if req.IsActive != nil {
		campaign.IsActive = *req.IsActive
	}

	err = s.db.Save(&campaign).Error
	if err != nil {
		return nil, err
	}

	// 加载关联数据
	err = s.db.Preload("ThreatActor").Preload("Creator").Preload("IOCs").First(&campaign, campaign.ID).Error
	if err != nil {
		return nil, err
	}

	return &campaign, nil
}

// Delete campaign
func (s *CampaignService) DeleteCampaign(id uint) error {
	// Start a transaction to ensure all deletes succeed or fail together
	tx := s.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Update related IOCs to remove campaign association
	if err := tx.Model(&models.IOC{}).Where("campaign_id = ?", id).Update("campaign_id", nil).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to update related IOCs: %w", err)
	}

	// Delete related activities
	if err := tx.Where("campaign_id = ?", id).Delete(&models.Activity{}).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete related activities: %w", err)
	}

	// Delete related campaign-actor relationships
	if err := tx.Where("campaign_id = ?", id).Delete(&models.CampaignActor{}).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete related campaign-actor relationships: %w", err)
	}

	// Finally, delete the campaign itself
	if err := tx.Delete(&models.Campaign{}, id).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete campaign: %w", err)
	}

	// Commit the transaction
	return tx.Commit().Error
}

// Search campaigns
func (s *CampaignService) SearchCampaigns(req CampaignSearchRequest) ([]models.Campaign, int64, error) {
	query := s.db.Model(&models.Campaign{})

	// Apply filter conditions
	if req.Name != "" {
		query = query.Where("name LIKE ?", "%"+req.Name+"%")
	}
	if req.ThreatActorID != 0 {
		query = query.Where("threat_actor_id = ?", req.ThreatActorID)
	}
	if req.IsActive != nil {
		query = query.Where("is_active = ?", *req.IsActive)
	}

	// Count total records
	var total int64
	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// Apply pagination
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.Limit <= 0 {
		req.Limit = 20
	}
	offset := (req.Page - 1) * req.Limit

	var campaigns []models.Campaign
	err = query.Preload("ThreatActor").Preload("Creator").Preload("IOCs").
		Offset(offset).Limit(req.Limit).Order("created_at DESC").Find(&campaigns).Error
	if err != nil {
		return nil, 0, err
	}

	return campaigns, total, nil
}

// Enhanced methods for threat activities management

// CampaignListParams represents parameters for listing campaigns (enhanced version)
type CampaignListParams struct {
	Page            int    `json:"page"`
	Limit           int    `json:"limit"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	Sophistication  string `json:"sophistication"`
	Scope           string `json:"scope"`
	Impact          string `json:"impact"`
	ThreatActorID   string `json:"threat_actor_id"`
	StartDateFrom   string `json:"start_date_from"`
	StartDateTo     string `json:"start_date_to"`
	IsActive        string `json:"is_active"`
}

// CampaignResponse represents the response structure for campaign lists
type CampaignResponse struct {
	Data  []models.Campaign `json:"data"`
	Total int64             `json:"total"`
	Page  int               `json:"page"`
	Limit int               `json:"limit"`
}

// GetCampaigns retrieves campaigns with enhanced filtering and pagination
func (s *CampaignService) GetCampaigns(params CampaignListParams) (*CampaignResponse, error) {
	var campaigns []models.Campaign
	var total int64

	// Build query with filters
	query := s.db.Model(&models.Campaign{})

	// Apply filters
	if params.Name != "" {
		query = query.Where("name LIKE ?", "%"+params.Name+"%")
	}
	if params.Status != "" {
		query = query.Where("status = ?", params.Status)
	}
	if params.Sophistication != "" {
		query = query.Where("sophistication = ?", params.Sophistication)
	}
	if params.Scope != "" {
		query = query.Where("scope = ?", params.Scope)
	}
	if params.Impact != "" {
		query = query.Where("impact = ?", params.Impact)
	}
	if params.ThreatActorID != "" {
		query = query.Where("threat_actor_id = ?", params.ThreatActorID)
	}
	if params.StartDateFrom != "" {
		query = query.Where("start_date >= ?", params.StartDateFrom)
	}
	if params.StartDateTo != "" {
		query = query.Where("start_date <= ?", params.StartDateTo)
	}
	if params.IsActive != "" {
		query = query.Where("is_active = ?", params.IsActive == "true")
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	// Apply pagination
	offset := (params.Page - 1) * params.Limit
	query = query.Offset(offset).Limit(params.Limit)

	// Order by created_at desc
	query = query.Order("created_at DESC")

	// Preload relationships
	query = query.Preload("ThreatActor").Preload("Creator").
		Preload("Activities").Preload("CampaignActors.ThreatActor").
		Preload("IOCs")

	// Execute query
	if err := query.Find(&campaigns).Error; err != nil {
		return nil, err
	}

	return &CampaignResponse{
		Data:  campaigns,
		Total: total,
		Page:  params.Page,
		Limit: params.Limit,
	}, nil
}

// AddThreatActorToCampaign associates a threat actor with a campaign
func (s *CampaignService) AddThreatActorToCampaign(campaignID, actorID uint, role string, confidenceLevel int) error {
	// Validate inputs
	if confidenceLevel < 0 || confidenceLevel > 100 {
		return errors.New("confidence level must be between 0 and 100")
	}

	// Check if campaign exists
	var campaign models.Campaign
	if err := s.db.First(&campaign, campaignID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.New("campaign not found")
		}
		return err
	}

	// Check if threat actor exists
	var actor models.ThreatActor
	if err := s.db.First(&actor, actorID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.New("threat actor not found")
		}
		return err
	}

	// Create or update the association
	campaignActor := models.CampaignActor{
		CampaignID:      campaignID,
		ThreatActorID:   actorID,
		Role:            role,
		ConfidenceLevel: confidenceLevel,
	}

	if err := s.db.Create(&campaignActor).Error; err != nil {
		// If it's a duplicate key error, update instead
		if err.Error() == "UNIQUE constraint failed: campaign_actors.campaign_id, campaign_actors.threat_actor_id" {
			return s.db.Model(&campaignActor).
				Where("campaign_id = ? AND threat_actor_id = ?", campaignID, actorID).
				Updates(map[string]interface{}{
					"role":             role,
					"confidence_level": confidenceLevel,
				}).Error
		}
		return err
	}

	return nil
}

// RemoveThreatActorFromCampaign removes a threat actor association from a campaign
func (s *CampaignService) RemoveThreatActorFromCampaign(campaignID, actorID uint) error {
	result := s.db.Where("campaign_id = ? AND threat_actor_id = ?", campaignID, actorID).
		Delete(&models.CampaignActor{})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return errors.New("association not found")
	}

	return nil
}

// GetCampaignStatistics returns statistics for campaigns
func (s *CampaignService) GetCampaignStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total campaigns
	var totalCampaigns int64
	if err := s.db.Model(&models.Campaign{}).Count(&totalCampaigns).Error; err != nil {
		return nil, err
	}
	stats["total_campaigns"] = totalCampaigns

	// Active campaigns
	var activeCampaigns int64
	if err := s.db.Model(&models.Campaign{}).Where("is_active = ?", true).Count(&activeCampaigns).Error; err != nil {
		return nil, err
	}
	stats["active_campaigns"] = activeCampaigns

	// Campaigns by status
	var statusCounts []struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}
	if err := s.db.Model(&models.Campaign{}).
		Select("status, COUNT(*) as count").
		Group("status").
		Scan(&statusCounts).Error; err != nil {
		return nil, err
	}
	stats["by_status"] = statusCounts

	return stats, nil
}
