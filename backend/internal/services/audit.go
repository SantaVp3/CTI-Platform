package services

import (
	"time"

	"cti-platform/internal/models"

	"gorm.io/gorm"
)

type AuditService struct {
	db *gorm.DB
}

type AuditLogEntry struct {
	UserID       *uint
	Action       string
	ResourceType string
	ResourceID   *uint
	OldValues    map[string]interface{}
	NewValues    map[string]interface{}
	IPAddress    string
	UserAgent    string
	Duration     time.Duration
	StatusCode   int
}

func NewAuditService(db *gorm.DB) *AuditService {
	return &AuditService{db: db}
}

func (s *AuditService) LogAction(entry AuditLogEntry) error {
	auditLog := models.AuditLog{
		UserID:       entry.UserID,
		Action:       entry.Action,
		ResourceType: entry.ResourceType,
		ResourceID:   entry.ResourceID,
		OldValues:    entry.OldValues,
		NewValues:    entry.NewValues,
		IPAddress:    entry.IPAddress,
		UserAgent:    entry.UserAgent,
	}

	return s.db.Create(&auditLog).Error
}
