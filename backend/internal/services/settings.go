package services

import (
	"encoding/json"
	"errors"
	"strconv"

	"gorm.io/gorm"

	"cti-platform/internal/models"
)

type SettingsService struct {
	db *gorm.DB
}

func NewSettingsService(db *gorm.DB) *SettingsService {
	return &SettingsService{db: db}
}

// System Settings request structures
type CreateSystemSettingRequest struct {
	Key         string `json:"key" binding:"required"`
	Value       string `json:"value" binding:"required"`
	Category    string `json:"category" binding:"required"`
	Description string `json:"description"`
	DataType    string `json:"data_type"`
	IsPublic    bool   `json:"is_public"`
}

type UpdateSystemSettingRequest struct {
	Value       *string `json:"value"`
	Description *string `json:"description"`
	IsPublic    *bool   `json:"is_public"`
}

// User Settings request structures
type CreateUserSettingRequest struct {
	Key      string `json:"key" binding:"required"`
	Value    string `json:"value" binding:"required"`
	Category string `json:"category" binding:"required"`
	DataType string `json:"data_type"`
}

type UpdateUserSettingRequest struct {
	Value *string `json:"value"`
}

// Security Policy request structures
type CreateSecurityPolicyRequest struct {
	Name                  string   `json:"name" binding:"required"`
	Description           string   `json:"description"`
	PasswordMinLength     int      `json:"password_min_length"`
	PasswordRequireUpper  bool     `json:"password_require_upper"`
	PasswordRequireLower  bool     `json:"password_require_lower"`
	PasswordRequireNumber bool     `json:"password_require_number"`
	PasswordRequireSymbol bool     `json:"password_require_symbol"`
	SessionTimeout        int      `json:"session_timeout"`
	MaxLoginAttempts      int      `json:"max_login_attempts"`
	LockoutDuration       int      `json:"lockout_duration"`
	TwoFactorRequired     bool     `json:"two_factor_required"`
	IPWhitelist           []string `json:"ip_whitelist"`
}

type UpdateSecurityPolicyRequest struct {
	Name                  *string  `json:"name"`
	Description           *string  `json:"description"`
	PasswordMinLength     *int     `json:"password_min_length"`
	PasswordRequireUpper  *bool    `json:"password_require_upper"`
	PasswordRequireLower  *bool    `json:"password_require_lower"`
	PasswordRequireNumber *bool    `json:"password_require_number"`
	PasswordRequireSymbol *bool    `json:"password_require_symbol"`
	SessionTimeout        *int     `json:"session_timeout"`
	MaxLoginAttempts      *int     `json:"max_login_attempts"`
	LockoutDuration       *int     `json:"lockout_duration"`
	TwoFactorRequired     *bool    `json:"two_factor_required"`
	IPWhitelist           []string `json:"ip_whitelist"`
	IsActive              *bool    `json:"is_active"`
}

// System Settings methods
func (s *SettingsService) CreateSystemSetting(req CreateSystemSettingRequest, userID uint) (*models.SystemSetting, error) {
	// Check if setting already exists
	var existing models.SystemSetting
	if err := s.db.Where("`key` = ?", req.Key).First(&existing).Error; err == nil {
		return nil, errors.New("setting with this key already exists")
	}

	// Set default data type
	if req.DataType == "" {
		req.DataType = "string"
	}

	setting := models.SystemSetting{
		Key:         req.Key,
		Value:       req.Value,
		Category:    req.Category,
		Description: req.Description,
		DataType:    req.DataType,
		IsPublic:    req.IsPublic,
		CreatedBy:   userID,
	}

	err := s.db.Create(&setting).Error
	if err != nil {
		return nil, err
	}

	// Load creator information
	err = s.db.Preload("Creator").First(&setting, setting.ID).Error
	if err != nil {
		return nil, err
	}

	return &setting, nil
}

func (s *SettingsService) GetSystemSettings(category string, isPublic *bool) ([]models.SystemSetting, error) {
	query := s.db.Model(&models.SystemSetting{})

	if category != "" {
		query = query.Where("category = ?", category)
	}
	if isPublic != nil {
		query = query.Where("is_public = ?", *isPublic)
	}

	var settings []models.SystemSetting
	err := query.Preload("Creator").Order("category, `key`").Find(&settings).Error
	return settings, err
}

func (s *SettingsService) GetSystemSetting(key string) (*models.SystemSetting, error) {
	var setting models.SystemSetting
	err := s.db.Preload("Creator").Where("`key` = ?", key).First(&setting).Error
	if err != nil {
		return nil, err
	}
	return &setting, nil
}

func (s *SettingsService) UpdateSystemSetting(key string, req UpdateSystemSettingRequest, userID uint) (*models.SystemSetting, error) {
	var setting models.SystemSetting
	err := s.db.Where("`key` = ?", key).First(&setting).Error
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if req.Value != nil {
		setting.Value = *req.Value
	}
	if req.Description != nil {
		setting.Description = *req.Description
	}
	if req.IsPublic != nil {
		setting.IsPublic = *req.IsPublic
	}

	err = s.db.Save(&setting).Error
	if err != nil {
		return nil, err
	}

	// Load creator information
	err = s.db.Preload("Creator").First(&setting, setting.ID).Error
	if err != nil {
		return nil, err
	}

	return &setting, nil
}

func (s *SettingsService) DeleteSystemSetting(key string) error {
	return s.db.Where("`key` = ?", key).Delete(&models.SystemSetting{}).Error
}

// User Settings methods
func (s *SettingsService) CreateUserSetting(req CreateUserSettingRequest, userID uint) (*models.UserSetting, error) {
	// Check if setting already exists for this user
	var existing models.UserSetting
	if err := s.db.Where("user_id = ? AND `key` = ?", userID, req.Key).First(&existing).Error; err == nil {
		return nil, errors.New("setting with this key already exists for user")
	}

	// Set default data type
	if req.DataType == "" {
		req.DataType = "string"
	}

	setting := models.UserSetting{
		UserID:   userID,
		Key:      req.Key,
		Value:    req.Value,
		Category: req.Category,
		DataType: req.DataType,
	}

	err := s.db.Create(&setting).Error
	if err != nil {
		return nil, err
	}

	// Load user information
	err = s.db.Preload("User").First(&setting, setting.ID).Error
	if err != nil {
		return nil, err
	}

	return &setting, nil
}

func (s *SettingsService) GetUserSettings(userID uint, category string) ([]models.UserSetting, error) {
	query := s.db.Where("user_id = ?", userID)

	if category != "" {
		query = query.Where("category = ?", category)
	}

	var settings []models.UserSetting
	err := query.Preload("User").Order("category, `key`").Find(&settings).Error
	return settings, err
}

func (s *SettingsService) GetUserSetting(userID uint, key string) (*models.UserSetting, error) {
	var setting models.UserSetting
	err := s.db.Preload("User").Where("user_id = ? AND `key` = ?", userID, key).First(&setting).Error
	if err != nil {
		return nil, err
	}
	return &setting, nil
}

func (s *SettingsService) UpdateUserSetting(userID uint, key string, req UpdateUserSettingRequest) (*models.UserSetting, error) {
	var setting models.UserSetting
	err := s.db.Where("user_id = ? AND `key` = ?", userID, key).First(&setting).Error
	if err != nil {
		return nil, err
	}

	// Update value if provided
	if req.Value != nil {
		setting.Value = *req.Value
	}

	err = s.db.Save(&setting).Error
	if err != nil {
		return nil, err
	}

	// Load user information
	err = s.db.Preload("User").First(&setting, setting.ID).Error
	if err != nil {
		return nil, err
	}

	return &setting, nil
}

func (s *SettingsService) DeleteUserSetting(userID uint, key string) error {
	return s.db.Where("user_id = ? AND `key` = ?", userID, key).Delete(&models.UserSetting{}).Error
}

// Helper methods for typed setting values
func (s *SettingsService) GetSystemSettingValue(key string, defaultValue interface{}) interface{} {
	setting, err := s.GetSystemSetting(key)
	if err != nil {
		return defaultValue
	}

	return parseSettingValue(setting.Value, setting.DataType, defaultValue)
}

func (s *SettingsService) GetUserSettingValue(userID uint, key string, defaultValue interface{}) interface{} {
	setting, err := s.GetUserSetting(userID, key)
	if err != nil {
		return defaultValue
	}

	return parseSettingValue(setting.Value, setting.DataType, defaultValue)
}

func parseSettingValue(value, dataType string, defaultValue interface{}) interface{} {
	switch dataType {
	case "boolean":
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	case "integer":
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	case "float":
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed
		}
	case "json":
		var parsed interface{}
		if err := json.Unmarshal([]byte(value), &parsed); err == nil {
			return parsed
		}
	default:
		return value
	}
	return defaultValue
}

// Security Policy methods
func (s *SettingsService) CreateSecurityPolicy(req CreateSecurityPolicyRequest, userID uint) (*models.SecurityPolicy, error) {
	// Convert IP whitelist to JSON
	ipWhitelistJSON := make(models.JSON)
	if req.IPWhitelist != nil {
		ipWhitelistJSON["ip_whitelist"] = req.IPWhitelist
	}

	policy := models.SecurityPolicy{
		Name:                  req.Name,
		Description:           req.Description,
		PasswordMinLength:     req.PasswordMinLength,
		PasswordRequireUpper:  req.PasswordRequireUpper,
		PasswordRequireLower:  req.PasswordRequireLower,
		PasswordRequireNumber: req.PasswordRequireNumber,
		PasswordRequireSymbol: req.PasswordRequireSymbol,
		SessionTimeout:        req.SessionTimeout,
		MaxLoginAttempts:      req.MaxLoginAttempts,
		LockoutDuration:       req.LockoutDuration,
		TwoFactorRequired:     req.TwoFactorRequired,
		IPWhitelist:           ipWhitelistJSON,
		CreatedBy:             userID,
	}

	// Set defaults if not provided
	if policy.PasswordMinLength == 0 {
		policy.PasswordMinLength = 8
	}
	if policy.SessionTimeout == 0 {
		policy.SessionTimeout = 3600
	}
	if policy.MaxLoginAttempts == 0 {
		policy.MaxLoginAttempts = 5
	}
	if policy.LockoutDuration == 0 {
		policy.LockoutDuration = 900
	}

	err := s.db.Create(&policy).Error
	if err != nil {
		return nil, err
	}

	// Load creator information
	err = s.db.Preload("Creator").First(&policy, policy.ID).Error
	if err != nil {
		return nil, err
	}

	return &policy, nil
}

func (s *SettingsService) GetSecurityPolicies() ([]models.SecurityPolicy, error) {
	var policies []models.SecurityPolicy
	err := s.db.Preload("Creator").Order("created_at DESC").Find(&policies).Error
	return policies, err
}

func (s *SettingsService) GetSecurityPolicy(id uint) (*models.SecurityPolicy, error) {
	var policy models.SecurityPolicy
	err := s.db.Preload("Creator").First(&policy, id).Error
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (s *SettingsService) GetActiveSecurityPolicy() (*models.SecurityPolicy, error) {
	var policy models.SecurityPolicy
	err := s.db.Preload("Creator").Where("is_active = ?", true).First(&policy).Error
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (s *SettingsService) UpdateSecurityPolicy(id uint, req UpdateSecurityPolicyRequest, userID uint) (*models.SecurityPolicy, error) {
	var policy models.SecurityPolicy
	err := s.db.First(&policy, id).Error
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if req.Name != nil {
		policy.Name = *req.Name
	}
	if req.Description != nil {
		policy.Description = *req.Description
	}
	if req.PasswordMinLength != nil {
		policy.PasswordMinLength = *req.PasswordMinLength
	}
	if req.PasswordRequireUpper != nil {
		policy.PasswordRequireUpper = *req.PasswordRequireUpper
	}
	if req.PasswordRequireLower != nil {
		policy.PasswordRequireLower = *req.PasswordRequireLower
	}
	if req.PasswordRequireNumber != nil {
		policy.PasswordRequireNumber = *req.PasswordRequireNumber
	}
	if req.PasswordRequireSymbol != nil {
		policy.PasswordRequireSymbol = *req.PasswordRequireSymbol
	}
	if req.SessionTimeout != nil {
		policy.SessionTimeout = *req.SessionTimeout
	}
	if req.MaxLoginAttempts != nil {
		policy.MaxLoginAttempts = *req.MaxLoginAttempts
	}
	if req.LockoutDuration != nil {
		policy.LockoutDuration = *req.LockoutDuration
	}
	if req.TwoFactorRequired != nil {
		policy.TwoFactorRequired = *req.TwoFactorRequired
	}
	if req.IPWhitelist != nil {
		ipWhitelistJSON := make(models.JSON)
		ipWhitelistJSON["ip_whitelist"] = req.IPWhitelist
		policy.IPWhitelist = ipWhitelistJSON
	}
	if req.IsActive != nil {
		// If activating this policy, deactivate others
		if *req.IsActive {
			s.db.Model(&models.SecurityPolicy{}).Where("id != ?", id).Update("is_active", false)
		}
		policy.IsActive = *req.IsActive
	}

	err = s.db.Save(&policy).Error
	if err != nil {
		return nil, err
	}

	// Load creator information
	err = s.db.Preload("Creator").First(&policy, policy.ID).Error
	if err != nil {
		return nil, err
	}

	return &policy, nil
}

func (s *SettingsService) DeleteSecurityPolicy(id uint) error {
	return s.db.Delete(&models.SecurityPolicy{}, id).Error
}

// Settings categories and defaults
func (s *SettingsService) GetSettingsCategories() []map[string]string {
	return []map[string]string{
		{"value": "general", "label": "General"},
		{"value": "security", "label": "Security"},
		{"value": "notifications", "label": "Notifications"},
		{"value": "appearance", "label": "Appearance"},
		{"value": "integrations", "label": "Integrations"},
		{"value": "backup", "label": "Backup & Recovery"},
		{"value": "audit", "label": "Audit & Logging"},
		{"value": "performance", "label": "Performance"},
	}
}

// Initialize default system settings
func (s *SettingsService) InitializeDefaultSettings(userID uint) error {
	defaultSettings := []models.SystemSetting{
		{Key: "platform_name", Value: "CTI Platform", Category: "general", Description: "Platform display name", DataType: "string", IsPublic: true, CreatedBy: userID},
		{Key: "platform_version", Value: "1.0.0", Category: "general", Description: "Platform version", DataType: "string", IsPublic: true, CreatedBy: userID},
		{Key: "max_upload_size", Value: "10485760", Category: "general", Description: "Maximum file upload size in bytes", DataType: "integer", IsPublic: false, CreatedBy: userID},
		{Key: "session_timeout", Value: "3600", Category: "security", Description: "Session timeout in seconds", DataType: "integer", IsPublic: false, CreatedBy: userID},
		{Key: "enable_audit_logging", Value: "true", Category: "audit", Description: "Enable audit logging", DataType: "boolean", IsPublic: false, CreatedBy: userID},
		{Key: "default_timezone", Value: "UTC", Category: "general", Description: "Default timezone", DataType: "string", IsPublic: true, CreatedBy: userID},
		{Key: "enable_notifications", Value: "true", Category: "notifications", Description: "Enable system notifications", DataType: "boolean", IsPublic: true, CreatedBy: userID},
		{Key: "threat_feed_update_interval", Value: "3600", Category: "integrations", Description: "Threat feed update interval in seconds", DataType: "integer", IsPublic: false, CreatedBy: userID},
	}

	for _, setting := range defaultSettings {
		// Check if setting already exists
		var existing models.SystemSetting
		if err := s.db.Where("`key` = ?", setting.Key).First(&existing).Error; err != nil {
			// Setting doesn't exist, create it
			if err := s.db.Create(&setting).Error; err != nil {
				return err
			}
		}
	}

	return nil
}
