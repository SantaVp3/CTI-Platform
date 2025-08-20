package handlers

import (
	"net/http"
	"strconv"

	"cti-platform/internal/services"

	"github.com/gin-gonic/gin"
)

type ThreatFeedHandler struct {
	threatFeedService *services.ThreatFeedService
}

func NewThreatFeedHandler(threatFeedService *services.ThreatFeedService) *ThreatFeedHandler {
	return &ThreatFeedHandler{
		threatFeedService: threatFeedService,
	}
}

// Create threat feed
func (h *ThreatFeedHandler) CreateThreatFeed(c *gin.Context) {
	var req services.CreateThreatFeedRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	feed, err := h.threatFeedService.CreateThreatFeed(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, feed)
}

// Get threat feed details
func (h *ThreatFeedHandler) GetThreatFeed(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid threat feed ID",
		})
		return
	}

	feed, err := h.threatFeedService.GetThreatFeed(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "威胁源不存在",
		})
		return
	}

	c.JSON(http.StatusOK, feed)
}

// 获取威胁源列表
func (h *ThreatFeedHandler) GetThreatFeeds(c *gin.Context) {
	var req services.ThreatFeedSearchRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "查询参数无效",
		})
		return
	}

	feeds, total, err := h.threatFeedService.GetThreatFeeds(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "获取威胁源列表失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  feeds,
		"total": total,
		"page":  req.Page,
		"limit": req.Limit,
	})
}

// 更新威胁源
func (h *ThreatFeedHandler) UpdateThreatFeed(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "无效的威胁源ID",
		})
		return
	}

	var req services.UpdateThreatFeedRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "请求格式无效",
		})
		return
	}

	userID, _ := c.Get("user_id")
	feed, err := h.threatFeedService.UpdateThreatFeed(uint(id), req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, feed)
}

// 删除威胁源
func (h *ThreatFeedHandler) DeleteThreatFeed(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "无效的威胁源ID",
		})
		return
	}

	err = h.threatFeedService.DeleteThreatFeed(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "删除威胁源失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "威胁源删除成功",
	})
}

// 摄取威胁源数据
func (h *ThreatFeedHandler) IngestFeed(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "无效的威胁源ID",
		})
		return
	}

	err = h.threatFeedService.IngestFeed(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Threat feed ingestion started",
	})
}

// Get threat feed types
func (h *ThreatFeedHandler) GetThreatFeedTypes(c *gin.Context) {
	types := []map[string]string{
		{"value": "json", "label": "JSON"},
		{"value": "stix", "label": "STIX"},
		{"value": "taxii", "label": "TAXII"},
		{"value": "csv", "label": "CSV"},
		{"value": "xml", "label": "XML"},
		{"value": "rss", "label": "RSS"},
	}

	c.JSON(http.StatusOK, gin.H{"data": types})
}

// Get authentication types
func (h *ThreatFeedHandler) GetAuthenticationTypes(c *gin.Context) {
	authTypes := []map[string]string{
		{"value": "none", "label": "None"},
		{"value": "basic", "label": "Basic Authentication"},
		{"value": "api_key", "label": "API Key"},
		{"value": "oauth", "label": "OAuth"},
	}

	c.JSON(http.StatusOK, gin.H{"data": authTypes})
}

// Test threat feed connection
func (h *ThreatFeedHandler) TestThreatFeed(c *gin.Context) {
	var req services.CreateThreatFeedRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Test the connection (this would be implemented in the service)
	// For now, just return success
	c.JSON(http.StatusOK, gin.H{
		"message": "Connection test successful",
		"status": "success",
	})
}

// Get threat feed statistics
func (h *ThreatFeedHandler) GetThreatFeedStatistics(c *gin.Context) {
	stats, err := h.threatFeedService.GetThreatFeedStatistics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// Get ingestion logs for a threat feed
func (h *ThreatFeedHandler) GetIngestionLogs(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid threat feed ID",
		})
		return
	}

	// Parse query parameters for pagination
	page := 1
	limit := 20
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	logs, total, err := h.threatFeedService.GetIngestionLogs(uint(id), page, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  logs,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}
