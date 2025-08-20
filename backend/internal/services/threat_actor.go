package services

import (
	"errors"
	"fmt"
	"time"

	"cti-platform/internal/models"

	"gorm.io/gorm"
)

type ThreatActorService struct {
	db *gorm.DB
}

// Create threat actor request structure
type CreateThreatActorRequest struct {
	Name            string                 `json:"name" binding:"required"`
	Aliases         []string               `json:"aliases"`
	Description     string                 `json:"description"`
	Country         string                 `json:"country"`
	Motivation      string                 `json:"motivation"`
	Sophistication  string                 `json:"sophistication"`
	ResourceLevel   string                 `json:"resource_level"`
	FirstSeen       *time.Time             `json:"first_seen"`
	LastSeen        *time.Time             `json:"last_seen"`
	ConfidenceLevel int                    `json:"confidence_level"`
}

// Update threat actor request structure
type UpdateThreatActorRequest struct {
	Name            *string    `json:"name"`
	Aliases         []string   `json:"aliases"`
	Description     *string    `json:"description"`
	Country         *string    `json:"country"`
	Motivation      *string    `json:"motivation"`
	Sophistication  *string    `json:"sophistication"`
	ResourceLevel   *string    `json:"resource_level"`
	FirstSeen       *time.Time `json:"first_seen"`
	LastSeen        *time.Time `json:"last_seen"`
	ConfidenceLevel *int       `json:"confidence_level"`
	IsActive        *bool      `json:"is_active"`
}

// Search threat actor request structure
type ThreatActorSearchRequest struct {
	Name          string `form:"name"`
	Country       string `form:"country"`
	Motivation    string `form:"motivation"`
	Sophistication string `form:"sophistication"`
	ResourceLevel string `form:"resource_level"`
	IsActive      *bool  `form:"is_active"`
	Page          int    `form:"page"`
	Limit         int    `form:"limit"`
}

func NewThreatActorService(db *gorm.DB) *ThreatActorService {
	return &ThreatActorService{db: db}
}

// Create threat actor
func (s *ThreatActorService) CreateThreatActor(req CreateThreatActorRequest, userID uint) (*models.ThreatActor, error) {
	// Check if threat actor name already exists
	var existingActor models.ThreatActor
	err := s.db.Where("name = ?", req.Name).First(&existingActor).Error
	if err == nil {
		return nil, errors.New("threat actor name already exists")
	}

	// Set default values
	if req.Motivation == "" {
		req.Motivation = "unknown"
	}
	if req.Sophistication == "" {
		req.Sophistication = "unknown"
	}
	if req.ResourceLevel == "" {
		req.ResourceLevel = "unknown"
	}
	if req.ConfidenceLevel == 0 {
		req.ConfidenceLevel = 50
	}

	// 转换别名为JSON格式
	aliases := make(map[string]interface{})
	if len(req.Aliases) > 0 {
		aliasArray := make([]interface{}, len(req.Aliases))
		for i, alias := range req.Aliases {
			aliasArray[i] = alias
		}
		aliases["aliases"] = aliasArray
	}

	actor := models.ThreatActor{
		Name:            req.Name,
		Aliases:         aliases,
		Description:     req.Description,
		Country:         req.Country,
		Motivation:      req.Motivation,
		Sophistication:  req.Sophistication,
		ResourceLevel:   req.ResourceLevel,
		FirstSeen:       req.FirstSeen,
		LastSeen:        req.LastSeen,
		IsActive:        true,
		ConfidenceLevel: req.ConfidenceLevel,
		CreatedBy:       userID,
	}

	err = s.db.Create(&actor).Error
	if err != nil {
		return nil, err
	}

	// 加载关联数据
	err = s.db.Preload("Creator").Preload("Campaigns").Preload("IOCs").First(&actor, actor.ID).Error
	if err != nil {
		return nil, err
	}

	return &actor, nil
}

// Get threat actor details
func (s *ThreatActorService) GetThreatActor(id uint) (*models.ThreatActor, error) {
	var actor models.ThreatActor
	err := s.db.Preload("Creator").Preload("Campaigns").Preload("IOCs").First(&actor, id).Error
	if err != nil {
		return nil, err
	}
	return &actor, nil
}

// Update threat actor
func (s *ThreatActorService) UpdateThreatActor(id uint, req UpdateThreatActorRequest, userID uint) (*models.ThreatActor, error) {
	var actor models.ThreatActor
	err := s.db.First(&actor, id).Error
	if err != nil {
		return nil, err
	}

	// If updating name, check for duplicates
	if req.Name != nil && *req.Name != actor.Name {
		var existingActor models.ThreatActor
		err = s.db.Where("name = ? AND id != ?", *req.Name, id).First(&existingActor).Error
		if err == nil {
			return nil, errors.New("threat actor name already exists")
		}
		actor.Name = *req.Name
	}

	// Update other fields
	if req.Description != nil {
		actor.Description = *req.Description
	}
	if req.Country != nil {
		actor.Country = *req.Country
	}
	if req.Motivation != nil {
		actor.Motivation = *req.Motivation
	}
	if req.Sophistication != nil {
		actor.Sophistication = *req.Sophistication
	}
	if req.ResourceLevel != nil {
		actor.ResourceLevel = *req.ResourceLevel
	}
	if req.FirstSeen != nil {
		actor.FirstSeen = req.FirstSeen
	}
	if req.LastSeen != nil {
		actor.LastSeen = req.LastSeen
	}
	if req.ConfidenceLevel != nil {
		actor.ConfidenceLevel = *req.ConfidenceLevel
	}
	if req.IsActive != nil {
		actor.IsActive = *req.IsActive
	}

	// Update aliases
	if req.Aliases != nil {
		aliases := make(map[string]interface{})
		if len(req.Aliases) > 0 {
			aliasArray := make([]interface{}, len(req.Aliases))
			for i, alias := range req.Aliases {
				aliasArray[i] = alias
			}
			aliases["aliases"] = aliasArray
		}
		actor.Aliases = aliases
	}

	err = s.db.Save(&actor).Error
	if err != nil {
		return nil, err
	}

	// Load associated data
	err = s.db.Preload("Creator").Preload("Campaigns").Preload("IOCs").First(&actor, actor.ID).Error
	if err != nil {
		return nil, err
	}

	return &actor, nil
}

// Delete threat actor
func (s *ThreatActorService) DeleteThreatActor(id uint) error {
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

	// Update related IOCs to remove threat actor association
	if err := tx.Model(&models.IOC{}).Where("threat_actor_id = ?", id).Update("threat_actor_id", nil).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to update related IOCs: %w", err)
	}

	// Update related campaigns to remove threat actor association
	if err := tx.Model(&models.Campaign{}).Where("threat_actor_id = ?", id).Update("threat_actor_id", nil).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to update related campaigns: %w", err)
	}

	// Delete related campaign-actor relationships
	if err := tx.Where("threat_actor_id = ?", id).Delete(&models.CampaignActor{}).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete related campaign-actor relationships: %w", err)
	}

	// Delete related activities
	if err := tx.Where("threat_actor_id = ?", id).Delete(&models.Activity{}).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete related activities: %w", err)
	}

	// Finally, delete the threat actor itself
	if err := tx.Delete(&models.ThreatActor{}, id).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete threat actor: %w", err)
	}

	// Commit the transaction
	return tx.Commit().Error
}

// Search threat actors
func (s *ThreatActorService) SearchThreatActors(req ThreatActorSearchRequest) ([]models.ThreatActor, int64, error) {
	query := s.db.Model(&models.ThreatActor{})

	// Apply filter conditions
	if req.Name != "" {
		query = query.Where("name LIKE ?", "%"+req.Name+"%")
	}
	if req.Country != "" {
		query = query.Where("country = ?", req.Country)
	}
	if req.Motivation != "" {
		query = query.Where("motivation = ?", req.Motivation)
	}
	if req.Sophistication != "" {
		query = query.Where("sophistication = ?", req.Sophistication)
	}
	if req.ResourceLevel != "" {
		query = query.Where("resource_level = ?", req.ResourceLevel)
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

	var actors []models.ThreatActor
	err = query.Preload("Creator").Preload("Campaigns").Preload("IOCs").
		Offset(offset).Limit(req.Limit).Order("created_at DESC").Find(&actors).Error
	if err != nil {
		return nil, 0, err
	}

	return actors, total, nil
}
