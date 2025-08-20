package services

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"cti-platform/internal/models"

	"gorm.io/gorm"
)

type IOCService struct {
	db *gorm.DB
}

type CreateIOCRequest struct {
	Value           string                 `json:"value" binding:"required"`
	TypeID          uint                   `json:"type_id" binding:"required"`
	ThreatActorID   *uint                  `json:"threat_actor_id"`
	CampaignID      *uint                  `json:"campaign_id"`
	Description     string                 `json:"description"`
	Tags            map[string]interface{} `json:"tags"`
	TLP             string                 `json:"tlp"`
	ConfidenceLevel int                    `json:"confidence_level"`
	Severity        string                 `json:"severity"`
	ExpirationDate  *time.Time             `json:"expiration_date"`
	Source          string                 `json:"source"`
}

type UpdateIOCRequest struct {
	Description     *string                `json:"description"`
	Tags            map[string]interface{} `json:"tags"`
	TLP             *string                `json:"tlp"`
	ConfidenceLevel *int                   `json:"confidence_level"`
	Severity        *string                `json:"severity"`
	ExpirationDate  *time.Time             `json:"expiration_date"`
	IsActive        *bool                  `json:"is_active"`
	FalsePositive   *bool                  `json:"false_positive"`
}

type IOCSearchRequest struct {
	Value         string `form:"value"`
	TypeID        uint   `form:"type_id"`
	ThreatActorID uint   `form:"threat_actor_id"`
	CampaignID    uint   `form:"campaign_id"`
	TLP           string `form:"tlp"`
	Severity      string `form:"severity"`
	IsActive      *bool  `form:"is_active"`
	FalsePositive *bool  `form:"false_positive"`
	Source        string `form:"source"`
	Page          int    `form:"page"`
	Limit         int    `form:"limit"`
}

func NewIOCService(db *gorm.DB) *IOCService {
	return &IOCService{db: db}
}

func (s *IOCService) CreateIOC(req CreateIOCRequest, userID uint) (*models.IOC, error) {
	// Validate IOC type exists
	var iocType models.IOCType
	err := s.db.First(&iocType, req.TypeID).Error
	if err != nil {
		return nil, errors.New("invalid IOC type")
	}

	// If there's a regex pattern, validate IOC value
	if iocType.PatternRegex != "" {
		matched, err := regexp.MatchString(iocType.PatternRegex, req.Value)
		if err != nil || !matched {
			return nil, fmt.Errorf("IOC值不符合类型 %s 的预期模式", iocType.Name)
		}
	}

	// 检查重复的IOC
	var existingIOC models.IOC
	err = s.db.Where("value = ? AND type_id = ?", req.Value, req.TypeID).First(&existingIOC).Error
	if err == nil {
		return nil, errors.New("IOC已存在")
	}

	// 设置默认值
	if req.TLP == "" {
		req.TLP = "white"
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}
	if req.ConfidenceLevel == 0 {
		req.ConfidenceLevel = 50
	}

	ioc := models.IOC{
		Value:           req.Value,
		TypeID:          req.TypeID,
		ThreatActorID:   req.ThreatActorID,
		CampaignID:      req.CampaignID,
		Description:     req.Description,
		Tags:            req.Tags,
		TLP:             req.TLP,
		ConfidenceLevel: req.ConfidenceLevel,
		Severity:        req.Severity,
		FirstSeen:       &[]time.Time{time.Now()}[0],
		LastSeen:        &[]time.Time{time.Now()}[0],
		ExpirationDate:  req.ExpirationDate,
		IsActive:        true,
		FalsePositive:   false,
		Source:          req.Source,
		CreatedBy:       userID,
	}

	err = s.db.Create(&ioc).Error
	if err != nil {
		return nil, err
	}

	// 加载关联数据
	err = s.db.Preload("Type").Preload("ThreatActor").Preload("Campaign").Preload("Creator").First(&ioc, ioc.ID).Error
	if err != nil {
		return nil, err
	}

	return &ioc, nil
}

func (s *IOCService) GetIOC(id uint) (*models.IOC, error) {
	var ioc models.IOC
	err := s.db.Preload("Type").Preload("ThreatActor").Preload("Campaign").Preload("Creator").Preload("AnalysisResults").First(&ioc, id).Error
	if err != nil {
		return nil, err
	}
	return &ioc, nil
}

func (s *IOCService) UpdateIOC(id uint, req UpdateIOCRequest, userID uint) (*models.IOC, error) {
	var ioc models.IOC
	err := s.db.First(&ioc, id).Error
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if req.Description != nil {
		ioc.Description = *req.Description
	}
	if req.Tags != nil {
		ioc.Tags = req.Tags
	}
	if req.TLP != nil {
		ioc.TLP = *req.TLP
	}
	if req.ConfidenceLevel != nil {
		ioc.ConfidenceLevel = *req.ConfidenceLevel
	}
	if req.Severity != nil {
		ioc.Severity = *req.Severity
	}
	if req.ExpirationDate != nil {
		ioc.ExpirationDate = req.ExpirationDate
	}
	if req.IsActive != nil {
		ioc.IsActive = *req.IsActive
	}
	if req.FalsePositive != nil {
		ioc.FalsePositive = *req.FalsePositive
	}

	now := time.Now()
	ioc.LastSeen = &now

	err = s.db.Save(&ioc).Error
	if err != nil {
		return nil, err
	}

	// Load relationships
	err = s.db.Preload("Type").Preload("ThreatActor").Preload("Campaign").Preload("Creator").First(&ioc, ioc.ID).Error
	if err != nil {
		return nil, err
	}

	return &ioc, nil
}

func (s *IOCService) DeleteIOC(id uint) error {
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

	// First, delete related analysis results
	if err := tx.Where("ioc_id = ?", id).Delete(&models.AnalysisResult{}).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete related analysis results: %w", err)
	}

	// Delete related activity-IOC relationships
	if err := tx.Where("ioc_id = ?", id).Delete(&models.ActivityIOC{}).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete related activity-IOC relationships: %w", err)
	}

	// Delete related report-IOC associations
	if err := tx.Where("ioc_id = ?", id).Delete(&models.ReportIOC{}).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete related report-IOC associations: %w", err)
	}

	// Finally, delete the IOC itself
	if err := tx.Delete(&models.IOC{}, id).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete IOC: %w", err)
	}

	// Commit the transaction
	return tx.Commit().Error
}

func (s *IOCService) SearchIOCs(req IOCSearchRequest) ([]models.IOC, int64, error) {
	query := s.db.Model(&models.IOC{})

	// Apply filters
	if req.Value != "" {
		query = query.Where("value LIKE ?", "%"+req.Value+"%")
	}
	if req.TypeID != 0 {
		query = query.Where("type_id = ?", req.TypeID)
	}
	if req.ThreatActorID != 0 {
		query = query.Where("threat_actor_id = ?", req.ThreatActorID)
	}
	if req.CampaignID != 0 {
		query = query.Where("campaign_id = ?", req.CampaignID)
	}
	if req.TLP != "" {
		query = query.Where("tlp = ?", req.TLP)
	}
	if req.Severity != "" {
		query = query.Where("severity = ?", req.Severity)
	}
	if req.IsActive != nil {
		query = query.Where("is_active = ?", *req.IsActive)
	}
	if req.FalsePositive != nil {
		query = query.Where("false_positive = ?", *req.FalsePositive)
	}
	if req.Source != "" {
		query = query.Where("source LIKE ?", "%"+req.Source+"%")
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

	var iocs []models.IOC
	err = query.Preload("Type").Preload("ThreatActor").Preload("Campaign").Preload("Creator").
		Offset(offset).Limit(req.Limit).Order("created_at DESC").Find(&iocs).Error
	if err != nil {
		return nil, 0, err
	}

	return iocs, total, nil
}

func (s *IOCService) GetIOCTypes() ([]models.IOCType, error) {
	var types []models.IOCType
	err := s.db.Find(&types).Error
	return types, err
}
