package services

import (
	"cti-platform/internal/config"

	"gorm.io/gorm"
)

// Services holds all service instances
type Services struct {
	DB           *gorm.DB
	Auth         *AuthService
	User         *UserService
	IOC          *IOCService
	ThreatActor  *ThreatActorService
	Campaign     *CampaignService
	Activity     *ActivityService
	ThreatFeed   *ThreatFeedService
	Analysis     *AnalysisService
	Report       *ReportService
	STIX         *STIXService
	Audit        *AuditService
	Notification *NotificationService
	Settings     *SettingsService
}

// NewServices creates and returns all service instances
func NewServices(db *gorm.DB, cfg *config.Config) *Services {
	return &Services{
		DB:           db,
		Auth:         NewAuthService(db, cfg),
		User:         NewUserService(db),
		IOC:          NewIOCService(db),
		ThreatActor:  NewThreatActorService(db),
		Campaign:     NewCampaignService(db),
		Activity:     NewActivityService(db),
		ThreatFeed:   NewThreatFeedService(db, cfg),
		Analysis:     NewAnalysisService(db, cfg),
		Report:       NewReportService(db),
		STIX:         NewSTIXService(db),
		Audit:        NewAuditService(db),
		Notification: NewNotificationService(db),
		Settings:     NewSettingsService(db),
	}
}
