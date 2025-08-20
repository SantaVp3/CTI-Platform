package services

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"cti-platform/internal/models"
)

// generateUUID creates a simple UUID-like string using crypto/rand
func generateUUID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

type STIXService struct {
	db *gorm.DB
}

func NewSTIXService(db *gorm.DB) *STIXService {
	return &STIXService{db: db}
}

// Create STIX object request structure
type CreateSTIXObjectRequest struct {
	STIXType     string                 `json:"stix_type" binding:"required"`
	SpecVersion  string                 `json:"spec_version"`
	ObjectData   map[string]interface{} `json:"object_data" binding:"required"`
	Labels       []string               `json:"labels"`
	ExternalRefs []map[string]interface{} `json:"external_references"`
}

// Update STIX object request structure
type UpdateSTIXObjectRequest struct {
	ObjectData   map[string]interface{} `json:"object_data"`
	Labels       []string               `json:"labels"`
	ExternalRefs []map[string]interface{} `json:"external_references"`
	Revoked      *bool                  `json:"revoked"`
}

// STIX object search request structure
type STIXObjectSearchRequest struct {
	STIXType    string `form:"stix_type"`
	Labels      string `form:"labels"`
	Revoked     *bool  `form:"revoked"`
	CreatedBy   uint   `form:"created_by"`
	CreatedFrom string `form:"created_from"`
	CreatedTo   string `form:"created_to"`
	Page        int    `form:"page"`
	Limit       int    `form:"limit"`
}

// Create STIX bundle request structure
type CreateSTIXBundleRequest struct {
	Name        string                   `json:"name" binding:"required"`
	Description string                   `json:"description"`
	Objects     []map[string]interface{} `json:"objects" binding:"required"`
}

// STIX relationship request structure
type CreateSTIXRelationshipRequest struct {
	RelationshipType string                 `json:"relationship_type" binding:"required"`
	SourceRef        string                 `json:"source_ref" binding:"required"`
	TargetRef        string                 `json:"target_ref" binding:"required"`
	ExternalRefs     []map[string]interface{} `json:"external_references"`
}

// Create STIX object
func (s *STIXService) CreateSTIXObject(req CreateSTIXObjectRequest, userID uint) (*models.STIXObject, error) {
	// Generate STIX ID
	stixID := fmt.Sprintf("%s--%s", req.STIXType, generateUUID())
	
	// Set default spec version
	if req.SpecVersion == "" {
		req.SpecVersion = "2.1"
	}
	
	// Validate STIX type
	if !isValidSTIXType(req.STIXType) {
		return nil, errors.New("invalid STIX object type")
	}
	
	// Ensure required STIX properties
	now := time.Now()
	req.ObjectData["id"] = stixID
	req.ObjectData["type"] = req.STIXType
	req.ObjectData["spec_version"] = req.SpecVersion
	req.ObjectData["created"] = now.Format(time.RFC3339)
	req.ObjectData["modified"] = now.Format(time.RFC3339)
	
	// Convert to JSON maps
	objectDataJSON := models.JSON(req.ObjectData)

	labelsJSON := make(models.JSON)
	if req.Labels != nil {
		labelsJSON["labels"] = req.Labels
	}

	externalRefsJSON := make(models.JSON)
	if req.ExternalRefs != nil {
		externalRefsJSON["external_references"] = req.ExternalRefs
	}
	
	stixObject := models.STIXObject{
		STIXID:       stixID,
		STIXType:     req.STIXType,
		SpecVersion:  req.SpecVersion,
		ObjectData:   objectDataJSON,
		Created:      now,
		Modified:     now,
		Labels:       labelsJSON,
		ExternalRefs: externalRefsJSON,
		CreatedBy:    userID,
	}

	err := s.db.Create(&stixObject).Error
	if err != nil {
		return nil, err
	}
	
	// Load creator information
	err = s.db.Preload("Creator").First(&stixObject, stixObject.ID).Error
	if err != nil {
		return nil, err
	}
	
	return &stixObject, nil
}

// Get STIX object details
func (s *STIXService) GetSTIXObject(id uint) (*models.STIXObject, error) {
	var stixObject models.STIXObject
	err := s.db.Preload("Creator").First(&stixObject, id).Error
	if err != nil {
		return nil, err
	}
	return &stixObject, nil
}

// Get STIX object by STIX ID
func (s *STIXService) GetSTIXObjectBySTIXID(stixID string) (*models.STIXObject, error) {
	var stixObject models.STIXObject
	err := s.db.Preload("Creator").Where("stix_id = ?", stixID).First(&stixObject).Error
	if err != nil {
		return nil, err
	}
	return &stixObject, nil
}

// Get STIX objects list
func (s *STIXService) GetSTIXObjects(req STIXObjectSearchRequest) ([]models.STIXObject, int64, error) {
	query := s.db.Model(&models.STIXObject{})
	
	// Apply filter conditions
	if req.STIXType != "" {
		query = query.Where("stix_type = ?", req.STIXType)
	}
	if req.Revoked != nil {
		query = query.Where("revoked = ?", *req.Revoked)
	}
	if req.CreatedBy != 0 {
		query = query.Where("created_by = ?", req.CreatedBy)
	}
	if req.CreatedFrom != "" {
		query = query.Where("created >= ?", req.CreatedFrom)
	}
	if req.CreatedTo != "" {
		query = query.Where("created <= ?", req.CreatedTo)
	}
	if req.Labels != "" {
		query = query.Where("JSON_CONTAINS(labels, ?)", fmt.Sprintf(`"%s"`, req.Labels))
	}
	
	// Count total records
	var total int64
	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}
	
	// Apply pagination
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.Limit <= 0 {
		req.Limit = 20
	}
	offset := (req.Page - 1) * req.Limit
	
	var stixObjects []models.STIXObject
	err = query.Preload("Creator").
		Order("created_at DESC").
		Offset(offset).
		Limit(req.Limit).
		Find(&stixObjects).Error
	
	return stixObjects, total, err
}

// Update STIX object
func (s *STIXService) UpdateSTIXObject(id uint, req UpdateSTIXObjectRequest, userID uint) (*models.STIXObject, error) {
	var stixObject models.STIXObject
	err := s.db.First(&stixObject, id).Error
	if err != nil {
		return nil, err
	}
	
	// Check ownership or admin privileges
	if stixObject.CreatedBy != userID {
		return nil, errors.New("unauthorized to update this STIX object")
	}
	
	// Update object data if provided
	if req.ObjectData != nil {
		// Get existing object data
		existingData := make(map[string]interface{})
		if stixObject.ObjectData != nil {
			existingData = map[string]interface{}(stixObject.ObjectData)
		}

		// Merge with new data
		for key, value := range req.ObjectData {
			existingData[key] = value
		}

		// Update modified timestamp
		existingData["modified"] = time.Now().Format(time.RFC3339)

		stixObject.ObjectData = models.JSON(existingData)
	}

	// Update other fields
	if req.Labels != nil {
		labelsJSON := make(models.JSON)
		labelsJSON["labels"] = req.Labels
		stixObject.Labels = labelsJSON
	}
	if req.ExternalRefs != nil {
		externalRefsJSON := make(models.JSON)
		externalRefsJSON["external_references"] = req.ExternalRefs
		stixObject.ExternalRefs = externalRefsJSON
	}
	if req.Revoked != nil {
		stixObject.Revoked = *req.Revoked
	}
	
	stixObject.Modified = time.Now()
	
	err = s.db.Save(&stixObject).Error
	if err != nil {
		return nil, err
	}
	
	// Load creator information
	err = s.db.Preload("Creator").First(&stixObject, stixObject.ID).Error
	if err != nil {
		return nil, err
	}
	
	return &stixObject, nil
}

// Delete STIX object
func (s *STIXService) DeleteSTIXObject(id uint, userID uint) error {
	var stixObject models.STIXObject
	err := s.db.First(&stixObject, id).Error
	if err != nil {
		return err
	}
	
	// Check ownership or admin privileges
	if stixObject.CreatedBy != userID {
		return errors.New("unauthorized to delete this STIX object")
	}
	
	return s.db.Delete(&stixObject).Error
}

// Validate STIX object type
func isValidSTIXType(stixType string) bool {
	validTypes := []string{
		// STIX Domain Objects (SDO)
		"attack-pattern", "campaign", "course-of-action", "grouping", "identity",
		"indicator", "infrastructure", "intrusion-set", "location", "malware",
		"malware-analysis", "note", "observed-data", "opinion", "report",
		"threat-actor", "tool", "vulnerability",
		// STIX Cyber-observable Objects (SCO)
		"artifact", "autonomous-system", "directory", "domain-name", "email-addr",
		"email-message", "file", "ipv4-addr", "ipv6-addr", "mac-addr", "mutex",
		"network-traffic", "process", "software", "url", "user-account",
		"windows-registry-key", "x509-certificate",
	}
	
	for _, validType := range validTypes {
		if stixType == validType {
			return true
		}
	}
	return false
}

// Create STIX bundle
func (s *STIXService) CreateSTIXBundle(req CreateSTIXBundleRequest, userID uint) (*models.STIXBundle, error) {
	// Generate bundle ID
	bundleID := fmt.Sprintf("bundle--%s", generateUUID())

	// Validate objects
	for _, obj := range req.Objects {
		if objType, ok := obj["type"].(string); !ok || !isValidSTIXType(objType) {
			return nil, errors.New("invalid STIX object type in bundle")
		}
	}

	// Convert objects to JSON
	objectsJSON := make(models.JSON)
	objectsJSON["objects"] = req.Objects

	bundle := models.STIXBundle{
		BundleID:    bundleID,
		SpecVersion: "2.1",
		Objects:     objectsJSON,
		Name:        req.Name,
		Description: req.Description,
		CreatedBy:   userID,
	}

	err := s.db.Create(&bundle).Error
	if err != nil {
		return nil, err
	}

	// Load creator information
	err = s.db.Preload("Creator").First(&bundle, bundle.ID).Error
	if err != nil {
		return nil, err
	}

	return &bundle, nil
}

// Get STIX bundle
func (s *STIXService) GetSTIXBundle(id uint) (*models.STIXBundle, error) {
	var bundle models.STIXBundle
	err := s.db.Preload("Creator").First(&bundle, id).Error
	if err != nil {
		return nil, err
	}
	return &bundle, nil
}

// Create STIX relationship
func (s *STIXService) CreateSTIXRelationship(req CreateSTIXRelationshipRequest, userID uint) (*models.STIXRelationship, error) {
	// Generate STIX ID
	stixID := fmt.Sprintf("relationship--%s", generateUUID())

	// Validate source and target references exist
	var sourceExists, targetExists bool
	s.db.Model(&models.STIXObject{}).Where("stix_id = ?", req.SourceRef).Select("count(*) > 0").Find(&sourceExists)
	s.db.Model(&models.STIXObject{}).Where("stix_id = ?", req.TargetRef).Select("count(*) > 0").Find(&targetExists)

	if !sourceExists {
		return nil, errors.New("source reference STIX object not found")
	}
	if !targetExists {
		return nil, errors.New("target reference STIX object not found")
	}

	// Convert external references to JSON
	externalRefsJSON := make(models.JSON)
	if req.ExternalRefs != nil {
		externalRefsJSON["external_references"] = req.ExternalRefs
	}

	now := time.Now()
	relationship := models.STIXRelationship{
		STIXID:           stixID,
		SpecVersion:      "2.1",
		RelationshipType: req.RelationshipType,
		SourceRef:        req.SourceRef,
		TargetRef:        req.TargetRef,
		Created:          now,
		Modified:         now,
		ExternalRefs:     externalRefsJSON,
		CreatedBy:        userID,
	}

	err := s.db.Create(&relationship).Error
	if err != nil {
		return nil, err
	}

	// Load creator information
	err = s.db.Preload("Creator").First(&relationship, relationship.ID).Error
	if err != nil {
		return nil, err
	}

	return &relationship, nil
}

// Get STIX statistics
func (s *STIXService) GetSTIXStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total STIX objects
	var totalObjects int64
	if err := s.db.Model(&models.STIXObject{}).Count(&totalObjects).Error; err != nil {
		return nil, err
	}
	stats["total_objects"] = totalObjects

	// Objects by type
	var typeCounts []struct {
		STIXType string `json:"stix_type"`
		Count    int64  `json:"count"`
	}
	if err := s.db.Model(&models.STIXObject{}).
		Select("stix_type, COUNT(*) as count").
		Group("stix_type").
		Scan(&typeCounts).Error; err != nil {
		return nil, err
	}
	stats["by_type"] = typeCounts

	// Total bundles
	var totalBundles int64
	if err := s.db.Model(&models.STIXBundle{}).Count(&totalBundles).Error; err != nil {
		return nil, err
	}
	stats["total_bundles"] = totalBundles

	// Total relationships
	var totalRelationships int64
	if err := s.db.Model(&models.STIXRelationship{}).Count(&totalRelationships).Error; err != nil {
		return nil, err
	}
	stats["total_relationships"] = totalRelationships

	// Recent objects (last 30 days)
	var recentObjects int64
	if err := s.db.Model(&models.STIXObject{}).
		Where("created_at > ?", time.Now().Add(-30*24*time.Hour)).
		Count(&recentObjects).Error; err != nil {
		return nil, err
	}
	stats["recent_objects"] = recentObjects

	return stats, nil
}

// Get STIX object types
func (s *STIXService) GetSTIXObjectTypes() []map[string]string {
	return []map[string]string{
		// STIX Domain Objects (SDO)
		{"value": "attack-pattern", "label": "Attack Pattern", "category": "SDO"},
		{"value": "campaign", "label": "Campaign", "category": "SDO"},
		{"value": "course-of-action", "label": "Course of Action", "category": "SDO"},
		{"value": "grouping", "label": "Grouping", "category": "SDO"},
		{"value": "identity", "label": "Identity", "category": "SDO"},
		{"value": "indicator", "label": "Indicator", "category": "SDO"},
		{"value": "infrastructure", "label": "Infrastructure", "category": "SDO"},
		{"value": "intrusion-set", "label": "Intrusion Set", "category": "SDO"},
		{"value": "location", "label": "Location", "category": "SDO"},
		{"value": "malware", "label": "Malware", "category": "SDO"},
		{"value": "malware-analysis", "label": "Malware Analysis", "category": "SDO"},
		{"value": "note", "label": "Note", "category": "SDO"},
		{"value": "observed-data", "label": "Observed Data", "category": "SDO"},
		{"value": "opinion", "label": "Opinion", "category": "SDO"},
		{"value": "report", "label": "Report", "category": "SDO"},
		{"value": "threat-actor", "label": "Threat Actor", "category": "SDO"},
		{"value": "tool", "label": "Tool", "category": "SDO"},
		{"value": "vulnerability", "label": "Vulnerability", "category": "SDO"},

		// STIX Cyber-observable Objects (SCO)
		{"value": "artifact", "label": "Artifact", "category": "SCO"},
		{"value": "autonomous-system", "label": "Autonomous System", "category": "SCO"},
		{"value": "directory", "label": "Directory", "category": "SCO"},
		{"value": "domain-name", "label": "Domain Name", "category": "SCO"},
		{"value": "email-addr", "label": "Email Address", "category": "SCO"},
		{"value": "email-message", "label": "Email Message", "category": "SCO"},
		{"value": "file", "label": "File", "category": "SCO"},
		{"value": "ipv4-addr", "label": "IPv4 Address", "category": "SCO"},
		{"value": "ipv6-addr", "label": "IPv6 Address", "category": "SCO"},
		{"value": "mac-addr", "label": "MAC Address", "category": "SCO"},
		{"value": "mutex", "label": "Mutex", "category": "SCO"},
		{"value": "network-traffic", "label": "Network Traffic", "category": "SCO"},
		{"value": "process", "label": "Process", "category": "SCO"},
		{"value": "software", "label": "Software", "category": "SCO"},
		{"value": "url", "label": "URL", "category": "SCO"},
		{"value": "user-account", "label": "User Account", "category": "SCO"},
		{"value": "windows-registry-key", "label": "Windows Registry Key", "category": "SCO"},
		{"value": "x509-certificate", "label": "X.509 Certificate", "category": "SCO"},
	}
}
