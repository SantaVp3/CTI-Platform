package handlers

import (
	"net/http"
	"strconv"

	"cti-platform/internal/services"

	"github.com/gin-gonic/gin"
)

type AnalysisHandler struct {
	analysisService *services.AnalysisService
}

func NewAnalysisHandler(analysisService *services.AnalysisService) *AnalysisHandler {
	return &AnalysisHandler{
		analysisService: analysisService,
	}
}

// 分析IOC
func (h *AnalysisHandler) AnalyzeIOC(c *gin.Context) {
	idStr := c.Param("id")
	iocID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "无效的IOC ID",
		})
		return
	}

	var reqBody struct {
		AnalysisType string `json:"analysis_type" binding:"required"`
		Analyzer     string `json:"analyzer"`
	}

	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "请求格式无效",
		})
		return
	}

	req := services.AnalyzeIOCRequest{
		IOCID:        uint(iocID),
		AnalysisType: reqBody.AnalysisType,
		Analyzer:     reqBody.Analyzer,
	}

	result, err := h.analysisService.AnalyzeIOC(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// 获取IOC分析结果
func (h *AnalysisHandler) GetAnalysisResults(c *gin.Context) {
	idStr := c.Param("ioc_id")
	iocID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "无效的IOC ID",
		})
		return
	}

	results, err := h.analysisService.GetAnalysisResults(uint(iocID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "获取分析结果失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": results,
	})
}

// 批量分析IOC
func (h *AnalysisHandler) BulkAnalyze(c *gin.Context) {
	var req services.BulkAnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "请求格式无效",
		})
		return
	}

	err := h.analysisService.BulkAnalyze(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "批量分析已开始",
	})
}
