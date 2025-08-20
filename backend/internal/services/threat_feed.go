package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"cti-platform/internal/config"
	"cti-platform/internal/models"

	"gorm.io/gorm"
)

type ThreatFeedService struct {
	db  *gorm.DB
	cfg *config.Config
}

// Create threat feed request structure
type CreateThreatFeedRequest struct {
	Name               string                 `json:"name" binding:"required"`
	Description        string                 `json:"description"`
	URL                string                 `json:"url" binding:"required"`
	FeedType           string                 `json:"feed_type"`
	AuthenticationType string                 `json:"authentication_type"`
	Credentials        map[string]interface{} `json:"credentials"`
	UpdateFrequency    int                    `json:"update_frequency"`
}

// Update threat feed request structure
type UpdateThreatFeedRequest struct {
	Name               *string                `json:"name"`
	Description        *string                `json:"description"`
	URL                *string                `json:"url"`
	FeedType           *string                `json:"feed_type"`
	AuthenticationType *string                `json:"authentication_type"`
	Credentials        map[string]interface{} `json:"credentials"`
	UpdateFrequency    *int                   `json:"update_frequency"`
	IsActive           *bool                  `json:"is_active"`
}

// Threat feed search request structure
type ThreatFeedSearchRequest struct {
	Name     string `form:"name"`
	FeedType string `form:"feed_type"`
	IsActive *bool  `form:"is_active"`
	Page     int    `form:"page"`
	Limit    int    `form:"limit"`
}

func NewThreatFeedService(db *gorm.DB, cfg *config.Config) *ThreatFeedService {
	return &ThreatFeedService{db: db, cfg: cfg}
}

// Create threat feed
func (s *ThreatFeedService) CreateThreatFeed(req CreateThreatFeedRequest, userID uint) (*models.ThreatFeed, error) {
	// Check if threat feed name already exists
	var existingFeed models.ThreatFeed
	err := s.db.Where("name = ?", req.Name).First(&existingFeed).Error
	if err == nil {
		return nil, errors.New("threat feed name already exists")
	}

	// Set default values
	if req.FeedType == "" {
		req.FeedType = "json"
	}
	if req.AuthenticationType == "" {
		req.AuthenticationType = "none"
	}
	if req.UpdateFrequency == 0 {
		req.UpdateFrequency = 3600 // Default 1 hour
	}

	feed := models.ThreatFeed{
		Name:               req.Name,
		Description:        req.Description,
		URL:                req.URL,
		FeedType:           req.FeedType,
		AuthenticationType: req.AuthenticationType,
		Credentials:        req.Credentials,
		UpdateFrequency:    req.UpdateFrequency,
		IsActive:           true,
		CreatedBy:          userID,
	}

	// Calculate next update time
	nextUpdate := time.Now().Add(time.Duration(req.UpdateFrequency) * time.Second)
	feed.NextUpdate = &nextUpdate

	err = s.db.Create(&feed).Error
	if err != nil {
		return nil, err
	}

	// Load associated data
	err = s.db.Preload("Creator").First(&feed, feed.ID).Error
	if err != nil {
		return nil, err
	}

	return &feed, nil
}

// Get threat feed details
func (s *ThreatFeedService) GetThreatFeed(id uint) (*models.ThreatFeed, error) {
	var feed models.ThreatFeed
	err := s.db.Preload("Creator").Preload("IngestionLogs").First(&feed, id).Error
	if err != nil {
		return nil, err
	}
	return &feed, nil
}

// Get threat feeds list
func (s *ThreatFeedService) GetThreatFeeds(req ThreatFeedSearchRequest) ([]models.ThreatFeed, int64, error) {
	query := s.db.Model(&models.ThreatFeed{})

	// Apply filter conditions
	if req.Name != "" {
		query = query.Where("name LIKE ?", "%"+req.Name+"%")
	}
	if req.FeedType != "" {
		query = query.Where("feed_type = ?", req.FeedType)
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

	var feeds []models.ThreatFeed
	err = query.Preload("Creator").
		Offset(offset).Limit(req.Limit).Order("created_at DESC").Find(&feeds).Error
	if err != nil {
		return nil, 0, err
	}

	return feeds, total, nil
}

// 更新威胁源
func (s *ThreatFeedService) UpdateThreatFeed(id uint, req UpdateThreatFeedRequest, userID uint) (*models.ThreatFeed, error) {
	var feed models.ThreatFeed
	err := s.db.First(&feed, id).Error
	if err != nil {
		return nil, err
	}

	// 如果更新名称，检查是否重复
	if req.Name != nil && *req.Name != feed.Name {
		var existingFeed models.ThreatFeed
		err = s.db.Where("name = ? AND id != ?", *req.Name, id).First(&existingFeed).Error
		if err == nil {
			return nil, errors.New("威胁源名称已存在")
		}
		feed.Name = *req.Name
	}

	// 更新其他字段
	if req.Description != nil {
		feed.Description = *req.Description
	}
	if req.URL != nil {
		feed.URL = *req.URL
	}
	if req.FeedType != nil {
		feed.FeedType = *req.FeedType
	}
	if req.AuthenticationType != nil {
		feed.AuthenticationType = *req.AuthenticationType
	}
	if req.Credentials != nil {
		feed.Credentials = req.Credentials
	}
	if req.UpdateFrequency != nil {
		feed.UpdateFrequency = *req.UpdateFrequency
		// 重新计算下次更新时间
		nextUpdate := time.Now().Add(time.Duration(*req.UpdateFrequency) * time.Second)
		feed.NextUpdate = &nextUpdate
	}
	if req.IsActive != nil {
		feed.IsActive = *req.IsActive
	}

	err = s.db.Save(&feed).Error
	if err != nil {
		return nil, err
	}

	// 加载关联数据
	err = s.db.Preload("Creator").First(&feed, feed.ID).Error
	if err != nil {
		return nil, err
	}

	return &feed, nil
}

// 删除威胁源
func (s *ThreatFeedService) DeleteThreatFeed(id uint) error {
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

	// Delete related ingestion logs
	if err := tx.Where("threat_feed_id = ?", id).Delete(&models.FeedIngestionLog{}).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete related ingestion logs: %w", err)
	}

	// Finally, delete the threat feed itself
	if err := tx.Delete(&models.ThreatFeed{}, id).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete threat feed: %w", err)
	}

	// Commit the transaction
	return tx.Commit().Error
}

// 摄取威胁源数据
func (s *ThreatFeedService) IngestFeed(id uint) error {
	var feed models.ThreatFeed
	err := s.db.First(&feed, id).Error
	if err != nil {
		return err
	}

	if !feed.IsActive {
		return errors.New("威胁源未激活")
	}

	// 创建摄取日志
	log := models.FeedIngestionLog{
		FeedID:    feed.ID,
		Status:    "success",
		StartedAt: time.Now(),
	}

	// 开始摄取过程
	err = s.performIngestion(&feed, &log)
	if err != nil {
		log.Status = "error"
		log.ErrorMessage = err.Error()
	}

	// 完成时间
	now := time.Now()
	log.CompletedAt = &now

	// 保存日志
	s.db.Create(&log)

	// 更新威胁源的最后更新时间和下次更新时间
	feed.LastUpdate = &now
	nextUpdate := now.Add(time.Duration(feed.UpdateFrequency) * time.Second)
	feed.NextUpdate = &nextUpdate
	s.db.Save(&feed)

	return err
}

// 执行实际的摄取操作
func (s *ThreatFeedService) performIngestion(feed *models.ThreatFeed, log *models.FeedIngestionLog) error {
	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 创建请求
	req, err := http.NewRequest("GET", feed.URL, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	// 添加认证信息
	err = s.addAuthentication(req, feed)
	if err != nil {
		return fmt.Errorf("添加认证信息失败: %v", err)
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP错误: %d", resp.StatusCode)
	}

	// 读取响应数据
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}

	// 根据威胁源类型解析数据
	return s.parseAndStoreFeedData(feed, data, log)
}

// 添加认证信息到请求
func (s *ThreatFeedService) addAuthentication(req *http.Request, feed *models.ThreatFeed) error {
	switch feed.AuthenticationType {
	case "basic":
		if username, ok := feed.Credentials["username"].(string); ok {
			if password, ok := feed.Credentials["password"].(string); ok {
				req.SetBasicAuth(username, password)
			}
		}
	case "api_key":
		if apiKey, ok := feed.Credentials["api_key"].(string); ok {
			if header, ok := feed.Credentials["header"].(string); ok {
				req.Header.Set(header, apiKey)
			} else {
				req.Header.Set("X-API-Key", apiKey)
			}
		}
	case "oauth":
		if token, ok := feed.Credentials["access_token"].(string); ok {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	return nil
}

// 解析并存储威胁源数据
func (s *ThreatFeedService) parseAndStoreFeedData(feed *models.ThreatFeed, data []byte, log *models.FeedIngestionLog) error {
	switch feed.FeedType {
	case "json":
		return s.parseJSONFeed(feed, data, log)
	case "stix":
		return s.parseSTIXFeed(feed, data, log)
	default:
		return fmt.Errorf("不支持的威胁源类型: %s", feed.FeedType)
	}
}

// 解析JSON格式的威胁源
func (s *ThreatFeedService) parseJSONFeed(feed *models.ThreatFeed, data []byte, log *models.FeedIngestionLog) error {
	var feedData map[string]interface{}
	err := json.Unmarshal(data, &feedData)
	if err != nil {
		return fmt.Errorf("JSON解析失败: %v", err)
	}

	// 这里应该根据具体的JSON格式来解析IOC
	// 简化实现，假设有indicators字段
	if indicators, ok := feedData["indicators"].([]interface{}); ok {
		log.RecordsProcessed = len(indicators)
		// 处理每个指标
		for _, indicator := range indicators {
			// 解析并创建IOC
			// 这里需要根据实际的数据格式来实现
			_ = indicator // 占位符，避免未使用变量错误
		}
	}

	return nil
}

// 解析STIX格式的威胁源
func (s *ThreatFeedService) parseSTIXFeed(feed *models.ThreatFeed, data []byte, log *models.FeedIngestionLog) error {
	var stixBundle map[string]interface{}
	err := json.Unmarshal(data, &stixBundle)
	if err != nil {
		return fmt.Errorf("STIX解析失败: %v", err)
	}

	// 检查是否为STIX Bundle
	if stixBundle["type"] != "bundle" {
		return errors.New("不是有效的STIX Bundle")
	}

	if objects, ok := stixBundle["objects"].([]interface{}); ok {
		log.RecordsProcessed = len(objects)
		// 处理每个STIX对象
		for _, obj := range objects {
			// Parse and create STIX objects
			// This would call STIX service to handle
			_ = obj // Placeholder to avoid unused variable error
		}
	}

	return nil
}

// Get threat feed statistics
func (s *ThreatFeedService) GetThreatFeedStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total feeds
	var totalFeeds int64
	if err := s.db.Model(&models.ThreatFeed{}).Count(&totalFeeds).Error; err != nil {
		return nil, err
	}
	stats["total_feeds"] = totalFeeds

	// Active feeds
	var activeFeeds int64
	if err := s.db.Model(&models.ThreatFeed{}).Where("is_active = ?", true).Count(&activeFeeds).Error; err != nil {
		return nil, err
	}
	stats["active_feeds"] = activeFeeds

	// Feeds by type
	var typeCounts []struct {
		FeedType string `json:"feed_type"`
		Count    int64  `json:"count"`
	}
	if err := s.db.Model(&models.ThreatFeed{}).
		Select("feed_type, COUNT(*) as count").
		Group("feed_type").
		Scan(&typeCounts).Error; err != nil {
		return nil, err
	}
	stats["by_type"] = typeCounts

	// Recent ingestion activity (last 24 hours)
	var recentIngestions int64
	if err := s.db.Model(&models.FeedIngestionLog{}).
		Where("created_at > ?", time.Now().Add(-24*time.Hour)).
		Count(&recentIngestions).Error; err != nil {
		return nil, err
	}
	stats["recent_ingestions"] = recentIngestions

	return stats, nil
}

// Get ingestion logs for a threat feed
func (s *ThreatFeedService) GetIngestionLogs(feedID uint, page, limit int) ([]models.FeedIngestionLog, int64, error) {
	var logs []models.FeedIngestionLog
	var total int64

	// Count total logs
	if err := s.db.Model(&models.FeedIngestionLog{}).
		Where("feed_id = ?", feedID).
		Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated logs
	offset := (page - 1) * limit
	if err := s.db.Where("feed_id = ?", feedID).
		Order("created_at DESC").
		Offset(offset).
		Limit(limit).
		Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}
