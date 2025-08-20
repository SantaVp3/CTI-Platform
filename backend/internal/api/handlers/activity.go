package handlers

import (
	"net/http"
	"strconv"

	"cti-platform/internal/models"
	"cti-platform/internal/services"
	"github.com/gin-gonic/gin"
)

type ActivityHandler struct {
	activityService *services.ActivityService
}

func NewActivityHandler(activityService *services.ActivityService) *ActivityHandler {
	return &ActivityHandler{
		activityService: activityService,
	}
}

// GetActivities handles GET /api/v1/activities
func (h *ActivityHandler) GetActivities(c *gin.Context) {
	// Parse query parameters
	params := services.ActivityListParams{
		Page:            parseIntParam(c, "page", 1),
		Limit:           parseIntParam(c, "limit", 10),
		Name:            c.Query("name"),
		ActivityType:    c.Query("activity_type"),
		Phase:           c.Query("phase"),
		Status:          c.Query("status"),
		Severity:        c.Query("severity"),
		CampaignID:      c.Query("campaign_id"),
		ThreatActorID:   c.Query("threat_actor_id"),
		StartTimeFrom:   c.Query("start_time_from"),
		StartTimeTo:     c.Query("start_time_to"),
		Location:        c.Query("location"),
		Source:          c.Query("source"),
	}

	// Validate pagination
	if params.Page < 1 {
		params.Page = 1
	}
	if params.Limit < 1 || params.Limit > 100 {
		params.Limit = 10
	}

	// Get activities
	response, err := h.activityService.GetActivities(params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetActivityByID handles GET /api/v1/activities/:id
func (h *ActivityHandler) GetActivityByID(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid activity ID"})
		return
	}

	activity, err := h.activityService.GetActivityByID(uint(id))
	if err != nil {
		if err.Error() == "activity not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Activity not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, activity)
}

// CreateActivity handles POST /api/v1/activities
func (h *ActivityHandler) CreateActivity(c *gin.Context) {
	var activity models.Activity
	if err := c.ShouldBindJSON(&activity); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set created_by from authenticated user
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	activity.CreatedBy = userID.(uint)

	if err := h.activityService.CreateActivity(&activity); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, activity)
}

// UpdateActivity handles PUT /api/v1/activities/:id
func (h *ActivityHandler) UpdateActivity(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid activity ID"})
		return
	}

	var updates models.Activity
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	activity, err := h.activityService.UpdateActivity(uint(id), &updates)
	if err != nil {
		if err.Error() == "activity not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Activity not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, activity)
}

// DeleteActivity handles DELETE /api/v1/activities/:id
func (h *ActivityHandler) DeleteActivity(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid activity ID"})
		return
	}

	if err := h.activityService.DeleteActivity(uint(id)); err != nil {
		if err.Error() == "activity not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Activity not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Activity deleted successfully"})
}

// GetActivityTimeline handles GET /api/v1/activities/timeline
func (h *ActivityHandler) GetActivityTimeline(c *gin.Context) {
	// Parse query parameters
	params := services.ActivityListParams{
		Page:            parseIntParam(c, "page", 1),
		Limit:           parseIntParam(c, "limit", 50),
		CampaignID:      c.Query("campaign_id"),
		ThreatActorID:   c.Query("threat_actor_id"),
		StartTimeFrom:   c.Query("start_time_from"),
		StartTimeTo:     c.Query("start_time_to"),
	}

	// Validate pagination
	if params.Page < 1 {
		params.Page = 1
	}
	if params.Limit < 1 || params.Limit > 200 {
		params.Limit = 50
	}

	// Get timeline activities
	response, err := h.activityService.GetActivityTimeline(params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetActivityTypes handles GET /api/v1/activities/types
func (h *ActivityHandler) GetActivityTypes(c *gin.Context) {
	types := []map[string]string{
		{"value": "reconnaissance", "label": "Reconnaissance"},
		{"value": "initial_access", "label": "Initial Access"},
		{"value": "execution", "label": "Execution"},
		{"value": "persistence", "label": "Persistence"},
		{"value": "privilege_escalation", "label": "Privilege Escalation"},
		{"value": "defense_evasion", "label": "Defense Evasion"},
		{"value": "credential_access", "label": "Credential Access"},
		{"value": "discovery", "label": "Discovery"},
		{"value": "lateral_movement", "label": "Lateral Movement"},
		{"value": "collection", "label": "Collection"},
		{"value": "command_control", "label": "Command & Control"},
		{"value": "exfiltration", "label": "Exfiltration"},
		{"value": "impact", "label": "Impact"},
		{"value": "other", "label": "Other"},
	}

	c.JSON(http.StatusOK, gin.H{"data": types})
}

// GetActivityPhases handles GET /api/v1/activities/phases
func (h *ActivityHandler) GetActivityPhases(c *gin.Context) {
	phases := []map[string]string{
		{"value": "preparation", "label": "Preparation"},
		{"value": "initial_compromise", "label": "Initial Compromise"},
		{"value": "establish_foothold", "label": "Establish Foothold"},
		{"value": "escalate_privileges", "label": "Escalate Privileges"},
		{"value": "internal_reconnaissance", "label": "Internal Reconnaissance"},
		{"value": "move_laterally", "label": "Move Laterally"},
		{"value": "maintain_presence", "label": "Maintain Presence"},
		{"value": "complete_mission", "label": "Complete Mission"},
	}

	c.JSON(http.StatusOK, gin.H{"data": phases})
}

// GetActivityStatuses handles GET /api/v1/activities/statuses
func (h *ActivityHandler) GetActivityStatuses(c *gin.Context) {
	statuses := []map[string]string{
		{"value": "planned", "label": "Planned"},
		{"value": "in_progress", "label": "In Progress"},
		{"value": "completed", "label": "Completed"},
		{"value": "failed", "label": "Failed"},
		{"value": "cancelled", "label": "Cancelled"},
	}

	c.JSON(http.StatusOK, gin.H{"data": statuses})
}

// GetActivitySeverities handles GET /api/v1/activities/severities
func (h *ActivityHandler) GetActivitySeverities(c *gin.Context) {
	severities := []map[string]string{
		{"value": "low", "label": "Low"},
		{"value": "medium", "label": "Medium"},
		{"value": "high", "label": "High"},
		{"value": "critical", "label": "Critical"},
	}

	c.JSON(http.StatusOK, gin.H{"data": severities})
}

// Helper function to parse integer parameters
func parseIntParam(c *gin.Context, param string, defaultValue int) int {
	if value := c.Query(param); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}
