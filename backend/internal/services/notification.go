package services

import (
	"fmt"

	"cti-platform/internal/models"

	"gorm.io/gorm"
)

type NotificationService struct {
	db *gorm.DB
}

// 创建通知请求结构
type CreateNotificationRequest struct {
	UserID  *uint  `json:"user_id"`
	Title   string `json:"title" binding:"required"`
	Message string `json:"message"`
	Type    string `json:"type"`
}

// 搜索通知请求结构
type NotificationSearchRequest struct {
	UserID uint   `form:"user_id"`
	Type   string `form:"type"`
	IsRead *bool  `form:"is_read"`
	Page   int    `form:"page"`
	Limit  int    `form:"limit"`
}

func NewNotificationService(db *gorm.DB) *NotificationService {
	return &NotificationService{db: db}
}

// 创建通知
func (s *NotificationService) CreateNotification(req CreateNotificationRequest) (*models.Notification, error) {
	// 设置默认值
	if req.Type == "" {
		req.Type = "info"
	}

	notification := models.Notification{
		UserID:  req.UserID,
		Title:   req.Title,
		Message: req.Message,
		Type:    req.Type,
		IsRead:  false,
	}

	err := s.db.Create(&notification).Error
	if err != nil {
		return nil, err
	}

	// 加载关联数据
	err = s.db.Preload("User").First(&notification, notification.ID).Error
	if err != nil {
		return nil, err
	}

	return &notification, nil
}

// 获取通知详情
func (s *NotificationService) GetNotification(id uint) (*models.Notification, error) {
	var notification models.Notification
	err := s.db.Preload("User").First(&notification, id).Error
	if err != nil {
		return nil, err
	}
	return &notification, nil
}

// 获取用户通知列表
func (s *NotificationService) GetNotifications(req NotificationSearchRequest) ([]models.Notification, int64, error) {
	query := s.db.Model(&models.Notification{})

	// 应用过滤条件
	if req.UserID != 0 {
		query = query.Where("user_id = ?", req.UserID)
	}
	if req.Type != "" {
		query = query.Where("type = ?", req.Type)
	}
	if req.IsRead != nil {
		query = query.Where("is_read = ?", *req.IsRead)
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

	var notifications []models.Notification
	err = query.Preload("User").
		Offset(offset).Limit(req.Limit).Order("created_at DESC").Find(&notifications).Error
	if err != nil {
		return nil, 0, err
	}

	return notifications, total, nil
}

// 标记通知为已读
func (s *NotificationService) MarkAsRead(id uint) error {
	return s.db.Model(&models.Notification{}).Where("id = ?", id).Update("is_read", true).Error
}

// 标记用户所有通知为已读
func (s *NotificationService) MarkAllAsRead(userID uint) error {
	return s.db.Model(&models.Notification{}).Where("user_id = ?", userID).Update("is_read", true).Error
}

// 删除通知
func (s *NotificationService) DeleteNotification(id uint) error {
	return s.db.Delete(&models.Notification{}, id).Error
}

// 删除用户所有已读通知
func (s *NotificationService) DeleteReadNotifications(userID uint) error {
	return s.db.Where("user_id = ? AND is_read = ?", userID, true).Delete(&models.Notification{}).Error
}

// 获取用户未读通知数量
func (s *NotificationService) GetUnreadCount(userID uint) (int64, error) {
	var count int64
	err := s.db.Model(&models.Notification{}).Where("user_id = ? AND is_read = ?", userID, false).Count(&count).Error
	return count, err
}

// 发送系统通知给所有用户
func (s *NotificationService) SendSystemNotification(title, message, notificationType string) error {
	// 获取所有活跃用户
	var users []models.User
	err := s.db.Where("is_active = ?", true).Find(&users).Error
	if err != nil {
		return err
	}

	// 为每个用户创建通知
	for _, user := range users {
		notification := models.Notification{
			UserID:  &user.ID,
			Title:   title,
			Message: message,
			Type:    notificationType,
			IsRead:  false,
		}
		s.db.Create(&notification)
	}

	return nil
}

// 发送威胁情报相关通知
func (s *NotificationService) SendThreatNotification(userID uint, threatType, message string) error {
	notification := models.Notification{
		UserID:  &userID,
		Title:   "威胁情报警报",
		Message: message,
		Type:    "warning",
		IsRead:  false,
	}

	return s.db.Create(&notification).Error
}

// 发送IOC分析完成通知
func (s *NotificationService) SendAnalysisCompleteNotification(userID uint, iocValue string, verdict string) error {
	title := "IOC分析完成"
	message := fmt.Sprintf("IOC %s 的分析已完成，结果：%s", iocValue, verdict)
	notificationType := "success"

	if verdict == "malicious" {
		notificationType = "error"
		title = "恶意IOC检测"
	}

	notification := models.Notification{
		UserID:  &userID,
		Title:   title,
		Message: message,
		Type:    notificationType,
		IsRead:  false,
	}

	return s.db.Create(&notification).Error
}
