package handlers

import (
	"net/http"
	"time"

	"cti-platform/internal/models"
	"cti-platform/internal/services"

	"github.com/gin-gonic/gin"
)

type DashboardHandler struct {
	services *services.Services
}

func NewDashboardHandler(services *services.Services) *DashboardHandler {
	return &DashboardHandler{
		services: services,
	}
}

// 仪表板统计数据结构
type DashboardStats struct {
	TotalIOCs         int64 `json:"total_iocs"`
	ActiveIOCs        int64 `json:"active_iocs"`
	MaliciousIOCs     int64 `json:"malicious_iocs"`
	TotalThreatActors int64 `json:"total_threat_actors"`
	ActiveCampaigns   int64 `json:"active_campaigns"`
	TotalReports      int64 `json:"total_reports"`
	RecentAnalyses    int64 `json:"recent_analyses"`
	ActiveFeeds       int64 `json:"active_feeds"`
}

// 最近活动结构
type RecentActivity struct {
	ID          uint      `json:"id"`
	Type        string    `json:"type"`        // "ioc", "report", "analysis", etc.
	Title       string    `json:"title"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

// 威胁趋势数据结构
type ThreatTrend struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
	Type  string `json:"type"`
}

// 获取仪表板统计数据
func (h *DashboardHandler) GetDashboardStats(c *gin.Context) {
	db := h.services.DB
	
	var stats DashboardStats
	
	// 统计IOC数据
	db.Model(&models.IOC{}).Count(&stats.TotalIOCs)
	db.Model(&models.IOC{}).Where("is_active = ?", true).Count(&stats.ActiveIOCs)
	
	// 统计恶意IOC（通过分析结果）
	db.Table("analysis_results").
		Joins("JOIN iocs ON analysis_results.ioc_id = iocs.id").
		Where("analysis_results.verdict = ? AND iocs.is_active = ?", "malicious", true).
		Count(&stats.MaliciousIOCs)
	
	// 统计威胁行为者
	db.Model(&models.ThreatActor{}).Where("is_active = ?", true).Count(&stats.TotalThreatActors)
	
	// 统计活跃活动
	db.Model(&models.Campaign{}).Where("is_active = ?", true).Count(&stats.ActiveCampaigns)
	
	// 统计报告
	db.Model(&models.Report{}).Count(&stats.TotalReports)
	
	// 统计最近24小时的分析
	yesterday := time.Now().Add(-24 * time.Hour)
	db.Model(&models.AnalysisResult{}).Where("analyzed_at > ?", yesterday).Count(&stats.RecentAnalyses)
	
	// 统计活跃威胁源
	db.Model(&models.ThreatFeed{}).Where("is_active = ?", true).Count(&stats.ActiveFeeds)
	
	c.JSON(http.StatusOK, stats)
}

// 获取最近活动
func (h *DashboardHandler) GetRecentActivity(c *gin.Context) {
	db := h.services.DB
	limit := 20
	
	var activities []RecentActivity
	
	// 获取最近的IOC
	var recentIOCs []models.IOC
	db.Preload("Creator").Preload("Type").
		Order("created_at DESC").Limit(limit/4).Find(&recentIOCs)
	
	for _, ioc := range recentIOCs {
		activity := RecentActivity{
			ID:          ioc.ID,
			Type:        "ioc",
			Title:       "新增IOC: " + ioc.Value,
			Description: "类型: " + ioc.Type.Name + ", 严重程度: " + ioc.Severity,
			CreatedAt:   ioc.CreatedAt,
		}
		if ioc.Creator.Username != "" {
			activity.CreatedBy = ioc.Creator.Username
		}
		activities = append(activities, activity)
	}
	
	// 获取最近的报告
	var recentReports []models.Report
	db.Preload("Creator").
		Order("created_at DESC").Limit(limit/4).Find(&recentReports)
	
	for _, report := range recentReports {
		activity := RecentActivity{
			ID:          report.ID,
			Type:        "report",
			Title:       "新增报告: " + report.Title,
			Description: "类型: " + report.ReportType + ", 状态: " + report.Status,
			CreatedAt:   report.CreatedAt,
		}
		if report.Creator.Username != "" {
			activity.CreatedBy = report.Creator.Username
		}
		activities = append(activities, activity)
	}
	
	// 获取最近的分析结果
	var recentAnalyses []models.AnalysisResult
	db.Preload("IOC").
		Order("analyzed_at DESC").Limit(limit/4).Find(&recentAnalyses)
	
	for _, analysis := range recentAnalyses {
		activity := RecentActivity{
			ID:          analysis.ID,
			Type:        "analysis",
			Title:       "IOC分析完成: " + analysis.IOC.Value,
			Description: "分析器: " + analysis.Analyzer + ", 结果: " + analysis.Verdict,
			CreatedAt:   analysis.AnalyzedAt,
			CreatedBy:   "系统",
		}
		activities = append(activities, activity)
	}
	
	// 获取最近的威胁行为者
	var recentActors []models.ThreatActor
	db.Preload("Creator").
		Order("created_at DESC").Limit(limit/4).Find(&recentActors)
	
	for _, actor := range recentActors {
		activity := RecentActivity{
			ID:          actor.ID,
			Type:        "threat_actor",
			Title:       "新增威胁行为者: " + actor.Name,
			Description: "动机: " + actor.Motivation + ", 复杂度: " + actor.Sophistication,
			CreatedAt:   actor.CreatedAt,
		}
		if actor.Creator.Username != "" {
			activity.CreatedBy = actor.Creator.Username
		}
		activities = append(activities, activity)
	}
	
	c.JSON(http.StatusOK, gin.H{
		"data": activities,
	})
}

// 获取威胁趋势数据
func (h *DashboardHandler) GetThreatTrends(c *gin.Context) {
	db := h.services.DB
	
	// 获取过去30天的数据
	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour)
	
	var trends []ThreatTrend
	
	// IOC趋势
	var iocTrends []struct {
		Date  string `json:"date"`
		Count int64  `json:"count"`
	}
	
	db.Model(&models.IOC{}).
		Select("DATE(created_at) as date, COUNT(*) as count").
		Where("created_at > ?", thirtyDaysAgo).
		Group("DATE(created_at)").
		Order("date").
		Find(&iocTrends)
	
	for _, trend := range iocTrends {
		trends = append(trends, ThreatTrend{
			Date:  trend.Date,
			Count: trend.Count,
			Type:  "ioc",
		})
	}
	
	// 恶意IOC趋势
	var maliciousTrends []struct {
		Date  string `json:"date"`
		Count int64  `json:"count"`
	}
	
	db.Table("analysis_results").
		Select("DATE(analyzed_at) as date, COUNT(*) as count").
		Where("analyzed_at > ? AND verdict = ?", thirtyDaysAgo, "malicious").
		Group("DATE(analyzed_at)").
		Order("date").
		Find(&maliciousTrends)
	
	for _, trend := range maliciousTrends {
		trends = append(trends, ThreatTrend{
			Date:  trend.Date,
			Count: trend.Count,
			Type:  "malicious",
		})
	}
	
	// 分析趋势
	var analysisTrends []struct {
		Date  string `json:"date"`
		Count int64  `json:"count"`
	}
	
	db.Model(&models.AnalysisResult{}).
		Select("DATE(analyzed_at) as date, COUNT(*) as count").
		Where("analyzed_at > ?", thirtyDaysAgo).
		Group("DATE(analyzed_at)").
		Order("date").
		Find(&analysisTrends)
	
	for _, trend := range analysisTrends {
		trends = append(trends, ThreatTrend{
			Date:  trend.Date,
			Count: trend.Count,
			Type:  "analysis",
		})
	}
	
	c.JSON(http.StatusOK, gin.H{
		"data": trends,
	})
}
