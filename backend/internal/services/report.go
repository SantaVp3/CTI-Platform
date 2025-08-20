package services

import (
	"errors"
	"time"

	"cti-platform/internal/models"

	"gorm.io/gorm"
)

type ReportService struct {
	db *gorm.DB
}

// Create report request structure
type CreateReportRequest struct {
	Title       string `json:"title" binding:"required"`
	Description string `json:"description"`
	Content     string `json:"content"`
	ReportType  string `json:"report_type"`
	TLP         string `json:"tlp"`
	IOCIDs      []uint `json:"ioc_ids"`
}

// Update report request structure
type UpdateReportRequest struct {
	Title       *string `json:"title"`
	Description *string `json:"description"`
	Content     *string `json:"content"`
	ReportType  *string `json:"report_type"`
	Status      *string `json:"status"`
	TLP         *string `json:"tlp"`
	IOCIDs      []uint  `json:"ioc_ids"`
}

// Report search request structure
type ReportSearchRequest struct {
	Title      string `form:"title"`
	ReportType string `form:"report_type"`
	Status     string `form:"status"`
	TLP        string `form:"tlp"`
	CreatedBy  uint   `form:"created_by"`
	Page       int    `form:"page"`
	Limit      int    `form:"limit"`
}

func NewReportService(db *gorm.DB) *ReportService {
	return &ReportService{db: db}
}

// Create report
func (s *ReportService) CreateReport(req CreateReportRequest, userID uint) (*models.Report, error) {
	// Set default values
	if req.ReportType == "" {
		req.ReportType = "custom"
	}
	if req.TLP == "" {
		req.TLP = "white"
	}

	report := models.Report{
		Title:       req.Title,
		Description: req.Description,
		Content:     req.Content,
		ReportType:  req.ReportType,
		Status:      "draft",
		TLP:         req.TLP,
		CreatedBy:   userID,
	}

	// Begin transaction
	tx := s.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Create report
	err := tx.Create(&report).Error
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	// Associate IOCs
	if len(req.IOCIDs) > 0 {
		for _, iocID := range req.IOCIDs {
			// Verify IOC exists
			var ioc models.IOC
			err = tx.First(&ioc, iocID).Error
			if err != nil {
				tx.Rollback()
				return nil, errors.New("specified IOC does not exist")
			}

			// Create association
			reportIOC := models.ReportIOC{
				ReportID: report.ID,
				IOCID:    iocID,
			}
			err = tx.Create(&reportIOC).Error
			if err != nil {
				tx.Rollback()
				return nil, err
			}
		}
	}

	// 提交事务
	err = tx.Commit().Error
	if err != nil {
		return nil, err
	}

	// 加载关联数据
	err = s.db.Preload("Creator").Preload("ReportIOCs.IOC").First(&report, report.ID).Error
	if err != nil {
		return nil, err
	}

	return &report, nil
}

// 获取报告详情
func (s *ReportService) GetReport(id uint) (*models.Report, error) {
	var report models.Report
	err := s.db.Preload("Creator").Preload("ReportIOCs.IOC").First(&report, id).Error
	if err != nil {
		return nil, err
	}
	return &report, nil
}

// 更新报告
func (s *ReportService) UpdateReport(id uint, req UpdateReportRequest, userID uint) (*models.Report, error) {
	var report models.Report
	err := s.db.First(&report, id).Error
	if err != nil {
		return nil, err
	}

	// 开始事务
	tx := s.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 更新字段
	if req.Title != nil {
		report.Title = *req.Title
	}
	if req.Description != nil {
		report.Description = *req.Description
	}
	if req.Content != nil {
		report.Content = *req.Content
	}
	if req.ReportType != nil {
		report.ReportType = *req.ReportType
	}
	if req.Status != nil {
		report.Status = *req.Status
	}
	if req.TLP != nil {
		report.TLP = *req.TLP
	}

	err = tx.Save(&report).Error
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	// 更新IOC关联
	if req.IOCIDs != nil {
		// 删除现有关联
		err = tx.Where("report_id = ?", id).Delete(&models.ReportIOC{}).Error
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		// 创建新关联
		for _, iocID := range req.IOCIDs {
			// 验证IOC存在性
			var ioc models.IOC
			err = tx.First(&ioc, iocID).Error
			if err != nil {
				tx.Rollback()
				return nil, errors.New("指定的IOC不存在")
			}

			// 创建关联
			reportIOC := models.ReportIOC{
				ReportID: report.ID,
				IOCID:    iocID,
			}
			err = tx.Create(&reportIOC).Error
			if err != nil {
				tx.Rollback()
				return nil, err
			}
		}
	}

	// 提交事务
	err = tx.Commit().Error
	if err != nil {
		return nil, err
	}

	// 加载关联数据
	err = s.db.Preload("Creator").Preload("ReportIOCs.IOC").First(&report, report.ID).Error
	if err != nil {
		return nil, err
	}

	return &report, nil
}

// 删除报告
func (s *ReportService) DeleteReport(id uint) error {
	return s.db.Delete(&models.Report{}, id).Error
}

// 搜索报告
func (s *ReportService) SearchReports(req ReportSearchRequest) ([]models.Report, int64, error) {
	query := s.db.Model(&models.Report{})

	// 应用过滤条件
	if req.Title != "" {
		query = query.Where("title LIKE ?", "%"+req.Title+"%")
	}
	if req.ReportType != "" {
		query = query.Where("report_type = ?", req.ReportType)
	}
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}
	if req.TLP != "" {
		query = query.Where("tlp = ?", req.TLP)
	}
	if req.CreatedBy != 0 {
		query = query.Where("created_by = ?", req.CreatedBy)
	}

	// 统计总记录数
	var total int64
	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// 应用分页
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.Limit <= 0 {
		req.Limit = 20
	}
	offset := (req.Page - 1) * req.Limit

	var reports []models.Report
	err = query.Preload("Creator").Preload("ReportIOCs.IOC").
		Offset(offset).Limit(req.Limit).Order("created_at DESC").Find(&reports).Error
	if err != nil {
		return nil, 0, err
	}

	return reports, total, nil
}

// 发布报告
func (s *ReportService) PublishReport(id uint) error {
	var report models.Report
	err := s.db.First(&report, id).Error
	if err != nil {
		return err
	}

	// Update status and publish time
	now := time.Now()
	report.Status = "published"
	report.PublishedAt = &now

	return s.db.Save(&report).Error
}

// Get report statistics
func (s *ReportService) GetReportStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total reports
	var totalReports int64
	if err := s.db.Model(&models.Report{}).Count(&totalReports).Error; err != nil {
		return nil, err
	}
	stats["total_reports"] = totalReports

	// Reports by status
	var statusCounts []struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}
	if err := s.db.Model(&models.Report{}).
		Select("status, COUNT(*) as count").
		Group("status").
		Scan(&statusCounts).Error; err != nil {
		return nil, err
	}
	stats["by_status"] = statusCounts

	// Reports by type
	var typeCounts []struct {
		ReportType string `json:"report_type"`
		Count      int64  `json:"count"`
	}
	if err := s.db.Model(&models.Report{}).
		Select("report_type, COUNT(*) as count").
		Group("report_type").
		Scan(&typeCounts).Error; err != nil {
		return nil, err
	}
	stats["by_type"] = typeCounts

	// Recent reports (last 30 days)
	var recentReports int64
	if err := s.db.Model(&models.Report{}).
		Where("created_at > ?", time.Now().Add(-30*24*time.Hour)).
		Count(&recentReports).Error; err != nil {
		return nil, err
	}
	stats["recent_reports"] = recentReports

	return stats, nil
}

// Get report types
func (s *ReportService) GetReportTypes() []map[string]string {
	return []map[string]string{
		{"value": "incident", "label": "Incident Report"},
		{"value": "threat_analysis", "label": "Threat Analysis"},
		{"value": "ioc_analysis", "label": "IOC Analysis"},
		{"value": "campaign_analysis", "label": "Campaign Analysis"},
		{"value": "actor_profile", "label": "Actor Profile"},
		{"value": "custom", "label": "Custom Report"},
	}
}

// Get TLP levels
func (s *ReportService) GetTLPLevels() []map[string]string {
	return []map[string]string{
		{"value": "red", "label": "TLP:RED"},
		{"value": "amber", "label": "TLP:AMBER"},
		{"value": "green", "label": "TLP:GREEN"},
		{"value": "white", "label": "TLP:WHITE"},
	}
}

// Export report to JSON
func (s *ReportService) ExportReportJSON(id uint) (map[string]interface{}, error) {
	var report models.Report
	err := s.db.Preload("Creator").
		Preload("ReportIOCs").
		Preload("ReportIOCs.IOC").
		First(&report, id).Error
	if err != nil {
		return nil, err
	}

	exportData := map[string]interface{}{
		"id":           report.ID,
		"title":        report.Title,
		"description":  report.Description,
		"content":      report.Content,
		"report_type":  report.ReportType,
		"status":       report.Status,
		"tlp":          report.TLP,
		"created_at":   report.CreatedAt,
		"updated_at":   report.UpdatedAt,
		"published_at": report.PublishedAt,
		"creator": map[string]interface{}{
			"id":       report.Creator.ID,
			"username": report.Creator.Username,
		},
		"iocs": report.ReportIOCs,
	}

	return exportData, nil
}

// Generate report template
func (s *ReportService) GenerateReportTemplate(reportType string) (string, error) {
	templates := map[string]string{
		"incident": `# Incident Report

## Executive Summary
[Brief overview of the incident]

## Incident Details
- **Date/Time**:
- **Affected Systems**:
- **Impact Level**:

## Technical Analysis
[Detailed technical analysis]

## Indicators of Compromise
[List of IOCs]

## Recommendations
[Recommended actions]

## Timeline
[Incident timeline]`,

		"threat_analysis": `# Threat Analysis Report

## Executive Summary
[Brief overview of the threat]

## Threat Overview
- **Threat Actor**:
- **Campaign**:
- **Target Sectors**:

## Technical Analysis
[Detailed technical analysis]

## TTPs (Tactics, Techniques, Procedures)
[MITRE ATT&CK mapping]

## Indicators of Compromise
[List of IOCs]

## Mitigation Strategies
[Recommended mitigations]`,

		"ioc_analysis": `# IOC Analysis Report

## Executive Summary
[Brief overview of the IOC analysis]

## IOC Details
[Detailed IOC information]

## Attribution
[Attribution analysis]

## Context and Relationships
[Related threats and campaigns]

## Detection and Response
[Detection rules and response procedures]`,
	}

	template, exists := templates[reportType]
	if !exists {
		template = templates["incident"] // Default template
	}

	return template, nil
}
