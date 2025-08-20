package handlers

import (
	"net/http"
	"strconv"

	"cti-platform/internal/services"

	"github.com/gin-gonic/gin"
)

type ThreatActorHandler struct {
	threatActorService *services.ThreatActorService
}

func NewThreatActorHandler(threatActorService *services.ThreatActorService) *ThreatActorHandler {
	return &ThreatActorHandler{
		threatActorService: threatActorService,
	}
}

// Create threat actor
func (h *ThreatActorHandler) CreateThreatActor(c *gin.Context) {
	var req services.CreateThreatActorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	actor, err := h.threatActorService.CreateThreatActor(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, actor)
}

// Get threat actor details
func (h *ThreatActorHandler) GetThreatActor(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid threat actor ID",
		})
		return
	}

	actor, err := h.threatActorService.GetThreatActor(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Threat actor not found",
		})
		return
	}

	c.JSON(http.StatusOK, actor)
}

// Search threat actors
func (h *ThreatActorHandler) SearchThreatActors(c *gin.Context) {
	var req services.ThreatActorSearchRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid query parameters",
		})
		return
	}

	actors, total, err := h.threatActorService.SearchThreatActors(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to search threat actors",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  actors,
		"total": total,
		"page":  req.Page,
		"limit": req.Limit,
	})
}

// Update threat actor
func (h *ThreatActorHandler) UpdateThreatActor(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid threat actor ID",
		})
		return
	}

	var req services.UpdateThreatActorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	actor, err := h.threatActorService.UpdateThreatActor(uint(id), req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, actor)
}

// Delete threat actor
func (h *ThreatActorHandler) DeleteThreatActor(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid threat actor ID",
		})
		return
	}

	err = h.threatActorService.DeleteThreatActor(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete threat actor",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Threat actor deleted successfully",
	})
}
