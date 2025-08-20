package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"cti-platform/internal/config"
	"cti-platform/internal/models"

	"gorm.io/gorm"
)

type AnalysisService struct {
	db  *gorm.DB
	cfg *config.Config
}

// Analysis request structure
type AnalyzeIOCRequest struct {
	IOCID        uint   `json:"ioc_id" binding:"required"`
	AnalysisType string `json:"analysis_type" binding:"required"`
	Analyzer     string `json:"analyzer"`
}

// Bulk analysis request structure
type BulkAnalyzeRequest struct {
	IOCIDs       []uint `json:"ioc_ids" binding:"required"`
	AnalysisType string `json:"analysis_type" binding:"required"`
	Analyzer     string `json:"analyzer"`
}

func NewAnalysisService(db *gorm.DB, cfg *config.Config) *AnalysisService {
	return &AnalysisService{db: db, cfg: cfg}
}

// 分析IOC
func (s *AnalysisService) AnalyzeIOC(req AnalyzeIOCRequest) (*models.AnalysisResult, error) {
	// 获取IOC信息
	var ioc models.IOC
	err := s.db.Preload("Type").First(&ioc, req.IOCID).Error
	if err != nil {
		return nil, fmt.Errorf("IOC不存在: %v", err)
	}

	// 设置默认分析器
	analyzer := req.Analyzer
	if analyzer == "" {
		analyzer = s.getDefaultAnalyzer(req.AnalysisType, ioc.Type.Name)
	}

	// Check if there are recent analysis results
	var existingResult models.AnalysisResult
	err = s.db.Where("ioc_id = ? AND analysis_type = ? AND analyzer = ? AND analyzed_at > ?",
		req.IOCID, req.AnalysisType, analyzer, time.Now().Add(-24*time.Hour)).
		First(&existingResult).Error
	if err == nil {
		// Return existing result
		return &existingResult, nil
	}

	// Perform analysis
	result, err := s.performAnalysis(ioc, req.AnalysisType, analyzer)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %v", err)
	}

	// Save analysis result
	analysisResult := models.AnalysisResult{
		IOCID:        req.IOCID,
		AnalysisType: req.AnalysisType,
		Analyzer:     analyzer,
		Result:       result.Data,
		Score:        result.Score,
		Verdict:      result.Verdict,
		AnalyzedAt:   time.Now(),
	}

	// Set expiration time (24 hours later)
	expiresAt := time.Now().Add(24 * time.Hour)
	analysisResult.ExpiresAt = &expiresAt

	err = s.db.Create(&analysisResult).Error
	if err != nil {
		return nil, err
	}

	// Load associated data
	err = s.db.Preload("IOC").First(&analysisResult, analysisResult.ID).Error
	if err != nil {
		return nil, err
	}

	return &analysisResult, nil
}

// Get IOC analysis results
func (s *AnalysisService) GetAnalysisResults(iocID uint) ([]models.AnalysisResult, error) {
	var results []models.AnalysisResult
	err := s.db.Where("ioc_id = ?", iocID).Order("analyzed_at DESC").Find(&results).Error
	return results, err
}

// Bulk analyze IOCs
func (s *AnalysisService) BulkAnalyze(req BulkAnalyzeRequest) error {
	for _, iocID := range req.IOCIDs {
		analyzeReq := AnalyzeIOCRequest{
			IOCID:        iocID,
			AnalysisType: req.AnalysisType,
			Analyzer:     req.Analyzer,
		}

		// Execute analysis asynchronously
		go func(r AnalyzeIOCRequest) {
			_, err := s.AnalyzeIOC(r)
			if err != nil {
				// Log error
				fmt.Printf("Bulk analysis of IOC %d failed: %v\n", r.IOCID, err)
			}
		}(analyzeReq)
	}

	return nil
}

// 分析结果结构
type AnalysisResultData struct {
	Data    map[string]interface{}
	Score   *int
	Verdict string
}

// 执行实际的分析
func (s *AnalysisService) performAnalysis(ioc models.IOC, analysisType, analyzer string) (*AnalysisResultData, error) {
	switch analyzer {
	case "virustotal":
		return s.analyzeWithVirusTotal(ioc, analysisType)
	case "shodan":
		return s.analyzeWithShodan(ioc, analysisType)
	default:
		return s.performBasicAnalysis(ioc, analysisType)
	}
}

// 获取默认分析器
func (s *AnalysisService) getDefaultAnalyzer(analysisType, iocType string) string {
	switch analysisType {
	case "reputation":
		if iocType == "ip" {
			return "shodan"
		}
		return "virustotal"
	case "enrichment":
		return "virustotal"
	default:
		return "basic"
	}
}

// 使用VirusTotal进行分析
func (s *AnalysisService) analyzeWithVirusTotal(ioc models.IOC, analysisType string) (*AnalysisResultData, error) {
	if s.cfg.External.VirusTotalAPIKey == "" {
		return s.performBasicAnalysis(ioc, analysisType)
	}

	// 构建VirusTotal API URL
	var url string
	switch ioc.Type.Name {
	case "ip":
		url = fmt.Sprintf("https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=%s&ip=%s",
			s.cfg.External.VirusTotalAPIKey, ioc.Value)
	case "domain":
		url = fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
			s.cfg.External.VirusTotalAPIKey, ioc.Value)
	case "md5", "sha1", "sha256":
		url = fmt.Sprintf("https://www.virustotal.com/vtapi/v2/file/report?apikey=%s&resource=%s",
			s.cfg.External.VirusTotalAPIKey, ioc.Value)
	default:
		return s.performBasicAnalysis(ioc, analysisType)
	}

	// 发送请求
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var vtResult map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&vtResult)
	if err != nil {
		return nil, err
	}

	// 解析结果
	score := 0
	verdict := "unknown"

	if positives, ok := vtResult["positives"].(float64); ok {
		if total, ok := vtResult["total"].(float64); ok && total > 0 {
			score = int((positives / total) * 100)
			if positives > 0 {
				verdict = "malicious"
			} else {
				verdict = "clean"
			}
		}
	}

	return &AnalysisResultData{
		Data:    vtResult,
		Score:   &score,
		Verdict: verdict,
	}, nil
}

// 使用Shodan进行分析
func (s *AnalysisService) analyzeWithShodan(ioc models.IOC, analysisType string) (*AnalysisResultData, error) {
	if s.cfg.External.ShodanAPIKey == "" || ioc.Type.Name != "ip" {
		return s.performBasicAnalysis(ioc, analysisType)
	}

	// 构建Shodan API URL
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s",
		ioc.Value, s.cfg.External.ShodanAPIKey)

	// 发送请求
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var shodanResult map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&shodanResult)
	if err != nil {
		return nil, err
	}

	// 解析结果
	score := 50 // 默认中等风险
	verdict := "unknown"

	// 根据开放端口和服务判断风险
	if ports, ok := shodanResult["ports"].([]interface{}); ok {
		if len(ports) > 10 {
			score = 70 // 开放端口较多，风险较高
			verdict = "suspicious"
		}
	}

	return &AnalysisResultData{
		Data:    shodanResult,
		Score:   &score,
		Verdict: verdict,
	}, nil
}

// 执行基本分析
func (s *AnalysisService) performBasicAnalysis(ioc models.IOC, analysisType string) (*AnalysisResultData, error) {
	// 基本分析逻辑
	result := map[string]interface{}{
		"analyzer": "basic",
		"type":     ioc.Type.Name,
		"value":    ioc.Value,
		"message":  "基本分析完成",
	}

	score := 50 // 默认中等风险
	verdict := "unknown"

	// 简单的启发式规则
	switch ioc.Type.Name {
	case "ip":
		// 检查是否为私有IP
		if s.isPrivateIP(ioc.Value) {
			score = 20
			verdict = "clean"
			result["note"] = "私有IP地址"
		}
	case "domain":
		// 检查域名长度和字符
		if len(ioc.Value) > 50 {
			score = 70
			verdict = "suspicious"
			result["note"] = "域名过长，可能为恶意域名"
		}
	}

	return &AnalysisResultData{
		Data:    result,
		Score:   &score,
		Verdict: verdict,
	}, nil
}

// 检查是否为私有IP
func (s *AnalysisService) isPrivateIP(ip string) bool {
	// 简化实现，实际应该使用更完整的IP解析
	privateRanges := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
		"172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
		"172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
		"127.", "169.254.",
	}

	for _, prefix := range privateRanges {
		if len(ip) >= len(prefix) && ip[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
