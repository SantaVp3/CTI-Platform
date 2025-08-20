package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"cti-platform/internal/services"
)

type STIXHandler struct {
	stixService *services.STIXService
}

func NewSTIXHandler(stixService *services.STIXService) *STIXHandler {
	return &STIXHandler{
		stixService: stixService,
	}
}

// Create STIX object
func (h *STIXHandler) CreateSTIXObject(c *gin.Context) {
	var req services.CreateSTIXObjectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	stixObject, err := h.stixService.CreateSTIXObject(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, stixObject)
}

// Get STIX object details
func (h *STIXHandler) GetSTIXObject(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid STIX object ID",
		})
		return
	}

	stixObject, err := h.stixService.GetSTIXObject(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "STIX object not found",
		})
		return
	}

	c.JSON(http.StatusOK, stixObject)
}

// Get STIX object by STIX ID
func (h *STIXHandler) GetSTIXObjectBySTIXID(c *gin.Context) {
	stixID := c.Param("stix_id")
	if stixID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "STIX ID is required",
		})
		return
	}

	stixObject, err := h.stixService.GetSTIXObjectBySTIXID(stixID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "STIX object not found",
		})
		return
	}

	c.JSON(http.StatusOK, stixObject)
}

// Get STIX objects list
func (h *STIXHandler) GetSTIXObjects(c *gin.Context) {
	var req services.STIXObjectSearchRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid query parameters",
		})
		return
	}

	stixObjects, total, err := h.stixService.GetSTIXObjects(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  stixObjects,
		"total": total,
		"page":  req.Page,
		"limit": req.Limit,
	})
}

// Update STIX object
func (h *STIXHandler) UpdateSTIXObject(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid STIX object ID",
		})
		return
	}

	var req services.UpdateSTIXObjectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	stixObject, err := h.stixService.UpdateSTIXObject(uint(id), req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, stixObject)
}

// Delete STIX object
func (h *STIXHandler) DeleteSTIXObject(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid STIX object ID",
		})
		return
	}

	userID, _ := c.Get("user_id")
	err = h.stixService.DeleteSTIXObject(uint(id), userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "STIX object deleted successfully",
	})
}

// Create STIX bundle
func (h *STIXHandler) CreateSTIXBundle(c *gin.Context) {
	var req services.CreateSTIXBundleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	bundle, err := h.stixService.CreateSTIXBundle(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, bundle)
}

// Get STIX bundle
func (h *STIXHandler) GetSTIXBundle(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid bundle ID",
		})
		return
	}

	bundle, err := h.stixService.GetSTIXBundle(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Bundle not found",
		})
		return
	}

	c.JSON(http.StatusOK, bundle)
}

// Create STIX relationship
func (h *STIXHandler) CreateSTIXRelationship(c *gin.Context) {
	var req services.CreateSTIXRelationshipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	relationship, err := h.stixService.CreateSTIXRelationship(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, relationship)
}

// Get STIX statistics
func (h *STIXHandler) GetSTIXStatistics(c *gin.Context) {
	stats, err := h.stixService.GetSTIXStatistics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// Get STIX object types
func (h *STIXHandler) GetSTIXObjectTypes(c *gin.Context) {
	types := h.stixService.GetSTIXObjectTypes()
	c.JSON(http.StatusOK, gin.H{"data": types})
}
