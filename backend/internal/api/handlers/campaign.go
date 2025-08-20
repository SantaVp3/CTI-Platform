package handlers

import (
	"net/http"
	"strconv"

	"cti-platform/internal/services"

	"github.com/gin-gonic/gin"
)

type CampaignHandler struct {
	campaignService *services.CampaignService
}

func NewCampaignHandler(campaignService *services.CampaignService) *CampaignHandler {
	return &CampaignHandler{
		campaignService: campaignService,
	}
}

// Create campaign
func (h *CampaignHandler) CreateCampaign(c *gin.Context) {
	var req services.CreateCampaignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	campaign, err := h.campaignService.CreateCampaign(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, campaign)
}

// Get campaign details
func (h *CampaignHandler) GetCampaign(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid campaign ID",
		})
		return
	}

	campaign, err := h.campaignService.GetCampaign(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Campaign not found",
		})
		return
	}

	c.JSON(http.StatusOK, campaign)
}

// Search campaigns
func (h *CampaignHandler) SearchCampaigns(c *gin.Context) {
	var req services.CampaignSearchRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid query parameters",
		})
		return
	}

	campaigns, total, err := h.campaignService.SearchCampaigns(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to search campaigns",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  campaigns,
		"total": total,
		"page":  req.Page,
		"limit": req.Limit,
	})
}

// Enhanced methods for threat activities management

// GetCampaignStatistics handles GET /api/v1/campaigns/statistics
func (h *CampaignHandler) GetCampaignStatistics(c *gin.Context) {
	stats, err := h.campaignService.GetCampaignStatistics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetCampaignStatuses handles GET /api/v1/campaigns/statuses
func (h *CampaignHandler) GetCampaignStatuses(c *gin.Context) {
	statuses := []map[string]string{
		{"value": "planning", "label": "Planning"},
		{"value": "active", "label": "Active"},
		{"value": "dormant", "label": "Dormant"},
		{"value": "completed", "label": "Completed"},
		{"value": "unknown", "label": "Unknown"},
	}

	c.JSON(http.StatusOK, gin.H{"data": statuses})
}

// GetCampaignSophistications handles GET /api/v1/campaigns/sophistications
func (h *CampaignHandler) GetCampaignSophistications(c *gin.Context) {
	sophistications := []map[string]string{
		{"value": "minimal", "label": "Minimal"},
		{"value": "intermediate", "label": "Intermediate"},
		{"value": "advanced", "label": "Advanced"},
		{"value": "expert", "label": "Expert"},
		{"value": "innovator", "label": "Innovator"},
		{"value": "unknown", "label": "Unknown"},
	}

	c.JSON(http.StatusOK, gin.H{"data": sophistications})
}

// GetCampaignScopes handles GET /api/v1/campaigns/scopes
func (h *CampaignHandler) GetCampaignScopes(c *gin.Context) {
	scopes := []map[string]string{
		{"value": "individual", "label": "Individual"},
		{"value": "organization", "label": "Organization"},
		{"value": "sector", "label": "Sector"},
		{"value": "regional", "label": "Regional"},
		{"value": "global", "label": "Global"},
		{"value": "unknown", "label": "Unknown"},
	}

	c.JSON(http.StatusOK, gin.H{"data": scopes})
}

// GetCampaignImpacts handles GET /api/v1/campaigns/impacts
func (h *CampaignHandler) GetCampaignImpacts(c *gin.Context) {
	impacts := []map[string]string{
		{"value": "low", "label": "Low"},
		{"value": "medium", "label": "Medium"},
		{"value": "high", "label": "High"},
		{"value": "critical", "label": "Critical"},
		{"value": "unknown", "label": "Unknown"},
	}

	c.JSON(http.StatusOK, gin.H{"data": impacts})
}

// GetCampaignActorRoles handles GET /api/v1/campaigns/actor-roles
func (h *CampaignHandler) GetCampaignActorRoles(c *gin.Context) {
	roles := []map[string]string{
		{"value": "primary", "label": "Primary"},
		{"value": "secondary", "label": "Secondary"},
		{"value": "collaborator", "label": "Collaborator"},
		{"value": "sponsor", "label": "Sponsor"},
		{"value": "unknown", "label": "Unknown"},
	}

	c.JSON(http.StatusOK, gin.H{"data": roles})
}

// AddThreatActorToCampaign handles POST /api/v1/campaigns/:id/actors
func (h *CampaignHandler) AddThreatActorToCampaign(c *gin.Context) {
	campaignID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid campaign ID"})
		return
	}

	var req struct {
		ThreatActorID   uint   `json:"threat_actor_id" binding:"required"`
		Role            string `json:"role"`
		ConfidenceLevel int    `json:"confidence_level"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.Role == "" {
		req.Role = "unknown"
	}
	if req.ConfidenceLevel == 0 {
		req.ConfidenceLevel = 50
	}

	if err := h.campaignService.AddThreatActorToCampaign(
		uint(campaignID), req.ThreatActorID, req.Role, req.ConfidenceLevel); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Threat actor associated with campaign successfully"})
}

// RemoveThreatActorFromCampaign handles DELETE /api/v1/campaigns/:id/actors/:actor_id
func (h *CampaignHandler) RemoveThreatActorFromCampaign(c *gin.Context) {
	campaignID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid campaign ID"})
		return
	}

	actorID, err := strconv.ParseUint(c.Param("actor_id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid threat actor ID"})
		return
	}

	if err := h.campaignService.RemoveThreatActorFromCampaign(uint(campaignID), uint(actorID)); err != nil {
		if err.Error() == "association not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Association not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Threat actor removed from campaign successfully"})
}

// Update campaign
func (h *CampaignHandler) UpdateCampaign(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid campaign ID",
		})
		return
	}

	var req services.UpdateCampaignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	campaign, err := h.campaignService.UpdateCampaign(uint(id), req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, campaign)
}

// Delete campaign
func (h *CampaignHandler) DeleteCampaign(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid campaign ID",
		})
		return
	}

	err = h.campaignService.DeleteCampaign(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete campaign",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Campaign deleted successfully",
	})
}
