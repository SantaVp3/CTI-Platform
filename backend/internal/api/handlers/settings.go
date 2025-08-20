package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"cti-platform/internal/services"
)

type SettingsHandler struct {
	settingsService *services.SettingsService
}

func NewSettingsHandler(settingsService *services.SettingsService) *SettingsHandler {
	return &SettingsHandler{
		settingsService: settingsService,
	}
}

// System Settings handlers

// Create system setting
func (h *SettingsHandler) CreateSystemSetting(c *gin.Context) {
	var req services.CreateSystemSettingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	setting, err := h.settingsService.CreateSystemSetting(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, setting)
}

// Get system settings
func (h *SettingsHandler) GetSystemSettings(c *gin.Context) {
	category := c.Query("category")
	isPublicStr := c.Query("is_public")
	
	var isPublic *bool
	if isPublicStr != "" {
		if parsed, err := strconv.ParseBool(isPublicStr); err == nil {
			isPublic = &parsed
		}
	}

	settings, err := h.settingsService.GetSystemSettings(category, isPublic)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": settings})
}

// Get system setting by key
func (h *SettingsHandler) GetSystemSetting(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Setting key is required",
		})
		return
	}

	setting, err := h.settingsService.GetSystemSetting(key)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Setting not found",
		})
		return
	}

	c.JSON(http.StatusOK, setting)
}

// Update system setting
func (h *SettingsHandler) UpdateSystemSetting(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Setting key is required",
		})
		return
	}

	var req services.UpdateSystemSettingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	setting, err := h.settingsService.UpdateSystemSetting(key, req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, setting)
}

// Delete system setting
func (h *SettingsHandler) DeleteSystemSetting(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Setting key is required",
		})
		return
	}

	err := h.settingsService.DeleteSystemSetting(key)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "System setting deleted successfully",
	})
}

// User Settings handlers

// Create user setting
func (h *SettingsHandler) CreateUserSetting(c *gin.Context) {
	var req services.CreateUserSettingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	setting, err := h.settingsService.CreateUserSetting(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, setting)
}

// Get user settings
func (h *SettingsHandler) GetUserSettings(c *gin.Context) {
	category := c.Query("category")
	userID, _ := c.Get("user_id")

	settings, err := h.settingsService.GetUserSettings(userID.(uint), category)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": settings})
}

// Get user setting by key
func (h *SettingsHandler) GetUserSetting(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Setting key is required",
		})
		return
	}

	userID, _ := c.Get("user_id")
	setting, err := h.settingsService.GetUserSetting(userID.(uint), key)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Setting not found",
		})
		return
	}

	c.JSON(http.StatusOK, setting)
}

// Update user setting
func (h *SettingsHandler) UpdateUserSetting(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Setting key is required",
		})
		return
	}

	var req services.UpdateUserSettingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	setting, err := h.settingsService.UpdateUserSetting(userID.(uint), key, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, setting)
}

// Delete user setting
func (h *SettingsHandler) DeleteUserSetting(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Setting key is required",
		})
		return
	}

	userID, _ := c.Get("user_id")
	err := h.settingsService.DeleteUserSetting(userID.(uint), key)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User setting deleted successfully",
	})
}

// Security Policy handlers

// Create security policy
func (h *SettingsHandler) CreateSecurityPolicy(c *gin.Context) {
	var req services.CreateSecurityPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	policy, err := h.settingsService.CreateSecurityPolicy(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, policy)
}

// Get security policies
func (h *SettingsHandler) GetSecurityPolicies(c *gin.Context) {
	policies, err := h.settingsService.GetSecurityPolicies()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": policies})
}

// Get security policy by ID
func (h *SettingsHandler) GetSecurityPolicy(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid policy ID",
		})
		return
	}

	policy, err := h.settingsService.GetSecurityPolicy(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Security policy not found",
		})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// Get active security policy
func (h *SettingsHandler) GetActiveSecurityPolicy(c *gin.Context) {
	policy, err := h.settingsService.GetActiveSecurityPolicy()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "No active security policy found",
		})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// Get settings categories
func (h *SettingsHandler) GetSettingsCategories(c *gin.Context) {
	categories := h.settingsService.GetSettingsCategories()
	c.JSON(http.StatusOK, gin.H{"data": categories})
}
