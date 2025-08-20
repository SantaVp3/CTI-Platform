package database

import (
	"fmt"
	"time"

	"cti-platform/internal/config"
	"cti-platform/internal/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

func Initialize(cfg *config.Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
	)

	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Auto-migrate models
	err = autoMigrate(db)
	if err != nil {
		return nil, fmt.Errorf("failed to auto-migrate: %w", err)
	}

	return db, nil
}

func autoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.User{},
		&models.ThreatActor{},
		&models.Campaign{},
		&models.IOCType{},
		&models.IOC{},
		&models.ThreatFeed{},
		&models.FeedIngestionLog{},
		&models.AnalysisResult{},
		&models.STIXObject{},
		&models.STIXBundle{},
		&models.STIXRelationship{},
		&models.Report{},
		&models.ReportIOC{},
		&models.AuditLog{},
		&models.APIKey{},
		&models.Session{},
		&models.Activity{},
		&models.CampaignActor{},
		&models.ActivityIOC{},
		&models.Notification{},
		&models.SystemSetting{},
		&models.UserSetting{},
		&models.SecurityPolicy{},
		&models.BackupConfiguration{},
	)
}

func GetDB() *gorm.DB {
	return db
}

func Close(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Transaction helper
func WithTransaction(fn func(*gorm.DB) error) error {
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}
