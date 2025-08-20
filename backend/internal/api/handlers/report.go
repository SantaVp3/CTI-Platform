package handlers

import (
	"net/http"
	"strconv"

	"cti-platform/internal/services"

	"github.com/gin-gonic/gin"
)

type ReportHandler struct {
	reportService *services.ReportService
}

func NewReportHandler(reportService *services.ReportService) *ReportHandler {
	return &ReportHandler{
		reportService: reportService,
	}
}

// Create report
func (h *ReportHandler) CreateReport(c *gin.Context) {
	var req services.CreateReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	report, err := h.reportService.CreateReport(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, report)
}

// Get report details
func (h *ReportHandler) GetReport(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid report ID",
		})
		return
	}

	report, err := h.reportService.GetReport(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "报告不存在",
		})
		return
	}

	c.JSON(http.StatusOK, report)
}

// 搜索报告
func (h *ReportHandler) SearchReports(c *gin.Context) {
	var req services.ReportSearchRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "查询参数无效",
		})
		return
	}

	reports, total, err := h.reportService.SearchReports(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "搜索报告失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  reports,
		"total": total,
		"page":  req.Page,
		"limit": req.Limit,
	})
}

// 更新报告
func (h *ReportHandler) UpdateReport(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "无效的报告ID",
		})
		return
	}

	var req services.UpdateReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "请求格式无效",
		})
		return
	}

	userID, _ := c.Get("user_id")
	report, err := h.reportService.UpdateReport(uint(id), req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, report)
}

// 删除报告
func (h *ReportHandler) DeleteReport(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "无效的报告ID",
		})
		return
	}

	err = h.reportService.DeleteReport(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "删除报告失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "报告删除成功",
	})
}

// 发布报告
func (h *ReportHandler) PublishReport(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "无效的报告ID",
		})
		return
	}

	err = h.reportService.PublishReport(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to publish report",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Report published successfully",
	})
}

// Get report statistics
func (h *ReportHandler) GetReportStatistics(c *gin.Context) {
	stats, err := h.reportService.GetReportStatistics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// Get report types
func (h *ReportHandler) GetReportTypes(c *gin.Context) {
	types := h.reportService.GetReportTypes()
	c.JSON(http.StatusOK, gin.H{"data": types})
}

// Get TLP levels
func (h *ReportHandler) GetTLPLevels(c *gin.Context) {
	levels := h.reportService.GetTLPLevels()
	c.JSON(http.StatusOK, gin.H{"data": levels})
}

// Export report as JSON
func (h *ReportHandler) ExportReportJSON(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid report ID",
		})
		return
	}

	exportData, err := h.reportService.ExportReportJSON(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Report not found",
		})
		return
	}

	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", "attachment; filename=report_"+idStr+".json")
	c.JSON(http.StatusOK, exportData)
}

// Generate report template
func (h *ReportHandler) GenerateReportTemplate(c *gin.Context) {
	reportType := c.Query("type")
	if reportType == "" {
		reportType = "incident"
	}

	template, err := h.reportService.GenerateReportTemplate(reportType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"template": template,
		"type":     reportType,
	})
}
