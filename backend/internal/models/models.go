package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

// JSON type for handling JSON fields
type JSON map[string]interface{}

func (j JSON) Value() (driver.Value, error) {
	return json.Marshal(j)
}

func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = make(JSON)
		return nil
	}
	
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	
	return json.Unmarshal(bytes, j)
}

// User model
type User struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Username     string    `json:"username" gorm:"uniqueIndex;size:50;not null"`
	Email        string    `json:"email" gorm:"uniqueIndex;size:100;not null"`
	PasswordHash string    `json:"-" gorm:"size:255;not null"`
	FirstName    string    `json:"first_name" gorm:"size:50"`
	LastName     string    `json:"last_name" gorm:"size:50"`
	Role         string    `json:"role" gorm:"type:enum('admin','analyst','viewer');default:'viewer'"`
	IsActive     bool      `json:"is_active" gorm:"default:true"`
	LastLogin    *time.Time `json:"last_login"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ThreatActor model
type ThreatActor struct {
	ID               uint      `json:"id" gorm:"primaryKey"`
	Name             string    `json:"name" gorm:"size:100;not null"`
	Aliases          JSON      `json:"aliases" gorm:"type:json"`
	Description      string    `json:"description" gorm:"type:text"`
	Country          string    `json:"country" gorm:"size:2"`
	Motivation       string    `json:"motivation" gorm:"type:enum('financial','espionage','hacktivism','warfare','unknown');default:'unknown'"`
	Sophistication   string    `json:"sophistication" gorm:"type:enum('minimal','intermediate','advanced','expert','innovator','unknown');default:'unknown'"`
	ResourceLevel    string    `json:"resource_level" gorm:"type:enum('individual','club','contest','team','organization','government','unknown');default:'unknown'"`
	FirstSeen        *time.Time `json:"first_seen" gorm:"type:date"`
	LastSeen         *time.Time `json:"last_seen" gorm:"type:date"`
	IsActive         bool      `json:"is_active" gorm:"default:true"`
	ConfidenceLevel  int       `json:"confidence_level" gorm:"default:50;check:confidence_level >= 0 AND confidence_level <= 100"`
	CreatedBy        uint      `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	
	// Relationships
	Creator   User       `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
	Campaigns []Campaign `json:"campaigns,omitempty" gorm:"foreignKey:ThreatActorID"`
	IOCs      []IOC      `json:"iocs,omitempty" gorm:"foreignKey:ThreatActorID"`
}

// Campaign model (Enhanced for Threat Activities)
type Campaign struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	Name            string    `json:"name" gorm:"size:100;not null"`
	Aliases         JSON      `json:"aliases" gorm:"type:json"`
	Description     string    `json:"description" gorm:"type:text"`
	Objectives      JSON      `json:"objectives" gorm:"type:json"`
	ThreatActorID   *uint     `json:"threat_actor_id"`
	StartDate       *time.Time `json:"start_date" gorm:"type:date"`
	EndDate         *time.Time `json:"end_date" gorm:"type:date"`
	Status          string    `json:"status" gorm:"type:enum('planning','active','dormant','completed','unknown');default:'unknown'"`
	Sophistication  string    `json:"sophistication" gorm:"type:enum('minimal','intermediate','advanced','expert','innovator','unknown');default:'unknown'"`
	Scope           string    `json:"scope" gorm:"type:enum('individual','organization','sector','regional','global','unknown');default:'unknown'"`
	Impact          string    `json:"impact" gorm:"type:enum('low','medium','high','critical','unknown');default:'unknown'"`
	TTP             JSON      `json:"ttp" gorm:"type:json"` // Tactics, Techniques, and Procedures
	TargetSectors   JSON      `json:"target_sectors" gorm:"type:json"`
	TargetCountries JSON      `json:"target_countries" gorm:"type:json"`
	IsActive        bool      `json:"is_active" gorm:"default:true"`
	ConfidenceLevel int       `json:"confidence_level" gorm:"default:50;check:confidence_level >= 0 AND confidence_level <= 100"`
	CreatedBy       uint      `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	// Relationships
	ThreatActor     *ThreatActor      `json:"threat_actor,omitempty" gorm:"foreignKey:ThreatActorID"`
	Creator         User              `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
	IOCs            []IOC             `json:"iocs,omitempty" gorm:"foreignKey:CampaignID"`
	Activities      []Activity        `json:"activities,omitempty" gorm:"foreignKey:CampaignID"`
	CampaignActors  []CampaignActor   `json:"campaign_actors,omitempty" gorm:"foreignKey:CampaignID"`
}

// IOCType model
type IOCType struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Name         string    `json:"name" gorm:"uniqueIndex;size:50;not null"`
	Description  string    `json:"description" gorm:"type:text"`
	PatternRegex string    `json:"pattern_regex" gorm:"size:500"`
	CreatedAt    time.Time `json:"created_at"`
	
	// Relationships
	IOCs []IOC `json:"iocs,omitempty" gorm:"foreignKey:TypeID"`
}

// IOC model
type IOC struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	Value           string    `json:"value" gorm:"size:500;not null"`
	TypeID          uint      `json:"type_id" gorm:"not null"`
	ThreatActorID   *uint     `json:"threat_actor_id"`
	CampaignID      *uint     `json:"campaign_id"`
	Description     string    `json:"description" gorm:"type:text"`
	Tags            JSON      `json:"tags" gorm:"type:json"`
	TLP             string    `json:"tlp" gorm:"type:enum('white','green','amber','red');default:'white'"`
	ConfidenceLevel int       `json:"confidence_level" gorm:"default:50;check:confidence_level >= 0 AND confidence_level <= 100"`
	Severity        string    `json:"severity" gorm:"type:enum('low','medium','high','critical');default:'medium'"`
	FirstSeen       *time.Time `json:"first_seen"`
	LastSeen        *time.Time `json:"last_seen"`
	ExpirationDate  *time.Time `json:"expiration_date"`
	IsActive        bool      `json:"is_active" gorm:"default:true"`
	FalsePositive   bool      `json:"false_positive" gorm:"default:false"`
	Source          string    `json:"source" gorm:"size:100"`
	CreatedBy       uint      `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	
	// Relationships
	Type           IOCType         `json:"type" gorm:"foreignKey:TypeID"`
	ThreatActor    *ThreatActor    `json:"threat_actor,omitempty" gorm:"foreignKey:ThreatActorID"`
	Campaign       *Campaign       `json:"campaign,omitempty" gorm:"foreignKey:CampaignID"`
	Creator        User            `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
	AnalysisResults []AnalysisResult `json:"analysis_results,omitempty" gorm:"foreignKey:IOCID"`
}

// ThreatFeed model
type ThreatFeed struct {
	ID                 uint      `json:"id" gorm:"primaryKey"`
	Name               string    `json:"name" gorm:"size:100;not null"`
	Description        string    `json:"description" gorm:"type:text"`
	URL                string    `json:"url" gorm:"size:500"`
	FeedType           string    `json:"feed_type" gorm:"type:enum('stix','taxii','json','csv','xml','rss');default:'json'"`
	AuthenticationType string    `json:"authentication_type" gorm:"type:enum('none','basic','api_key','oauth');default:'none'"`
	Credentials        JSON      `json:"credentials" gorm:"type:json"`
	UpdateFrequency    int       `json:"update_frequency" gorm:"default:3600"`
	LastUpdate         *time.Time `json:"last_update"`
	NextUpdate         *time.Time `json:"next_update"`
	IsActive           bool      `json:"is_active" gorm:"default:true"`
	CreatedBy          uint      `json:"created_by"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	
	// Relationships
	Creator        User                `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
	IngestionLogs  []FeedIngestionLog  `json:"ingestion_logs,omitempty" gorm:"foreignKey:FeedID"`
}

// FeedIngestionLog model
type FeedIngestionLog struct {
	ID               uint      `json:"id" gorm:"primaryKey"`
	FeedID           uint      `json:"feed_id" gorm:"not null"`
	Status           string    `json:"status" gorm:"type:enum('success','error','partial');not null"`
	RecordsProcessed int       `json:"records_processed" gorm:"default:0"`
	RecordsAdded     int       `json:"records_added" gorm:"default:0"`
	RecordsUpdated   int       `json:"records_updated" gorm:"default:0"`
	ErrorMessage     string    `json:"error_message" gorm:"type:text"`
	StartedAt        time.Time `json:"started_at"`
	CompletedAt      *time.Time `json:"completed_at"`

	// Relationships
	Feed ThreatFeed `json:"feed" gorm:"foreignKey:FeedID"`
}

// AnalysisResult model
type AnalysisResult struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	IOCID        uint      `json:"ioc_id" gorm:"not null"`
	AnalysisType string    `json:"analysis_type" gorm:"type:enum('reputation','enrichment','sandbox','static','dynamic');not null"`
	Analyzer     string    `json:"analyzer" gorm:"size:100;not null"`
	Result       JSON      `json:"result" gorm:"type:json;not null"`
	Score        *int      `json:"score" gorm:"check:score >= 0 AND score <= 100"`
	Verdict      string    `json:"verdict" gorm:"type:enum('clean','suspicious','malicious','unknown');default:'unknown'"`
	AnalyzedAt   time.Time `json:"analyzed_at"`
	ExpiresAt    *time.Time `json:"expires_at"`

	// Relationships
	IOC IOC `json:"ioc" gorm:"foreignKey:IOCID"`
}

// STIXObject model
type STIXObject struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	STIXID      string    `json:"stix_id" gorm:"uniqueIndex;size:100;not null"`
	STIXType    string    `json:"stix_type" gorm:"size:50;not null"`
	SpecVersion string    `json:"spec_version" gorm:"size:10;default:'2.1'"`
	ObjectData  JSON      `json:"object_data" gorm:"type:json;not null"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Revoked     bool      `json:"revoked" gorm:"default:false"`
	Labels      JSON      `json:"labels" gorm:"type:json"`
	ExternalRefs JSON     `json:"external_references" gorm:"type:json"`
	CreatedBy   uint      `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relationships
	Creator *User `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
}

// STIXBundle model for managing collections of STIX objects
type STIXBundle struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	BundleID    string    `json:"bundle_id" gorm:"uniqueIndex;size:100;not null"`
	SpecVersion string    `json:"spec_version" gorm:"size:10;default:'2.1'"`
	Objects     JSON      `json:"objects" gorm:"type:json;not null"`
	Name        string    `json:"name" gorm:"size:200"`
	Description string    `json:"description" gorm:"type:text"`
	CreatedBy   uint      `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relationships
	Creator *User `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
}

// STIXRelationship model for STIX Relationship Objects (SRO)
type STIXRelationship struct {
	ID               uint      `json:"id" gorm:"primaryKey"`
	STIXID           string    `json:"stix_id" gorm:"uniqueIndex;size:100;not null"`
	SpecVersion      string    `json:"spec_version" gorm:"size:10;default:'2.1'"`
	RelationshipType string    `json:"relationship_type" gorm:"size:50;not null"`
	SourceRef        string    `json:"source_ref" gorm:"size:100;not null"`
	TargetRef        string    `json:"target_ref" gorm:"size:100;not null"`
	Created          time.Time `json:"created"`
	Modified         time.Time `json:"modified"`
	Revoked          bool      `json:"revoked" gorm:"default:false"`
	ExternalRefs     JSON      `json:"external_references" gorm:"type:json"`
	CreatedBy        uint      `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`

	// Relationships
	Creator *User `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
}

// Report model
type Report struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Title       string    `json:"title" gorm:"size:200;not null"`
	Description string    `json:"description" gorm:"type:text"`
	Content     string    `json:"content" gorm:"type:longtext"`
	ReportType  string    `json:"report_type" gorm:"type:enum('incident','campaign','actor','ioc','custom');default:'custom'"`
	Status      string    `json:"status" gorm:"type:enum('draft','review','published','archived');default:'draft'"`
	TLP         string    `json:"tlp" gorm:"type:enum('white','green','amber','red');default:'white'"`
	CreatedBy   uint      `json:"created_by"`
	PublishedAt *time.Time `json:"published_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relationships
	Creator    User        `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
	ReportIOCs []ReportIOC `json:"report_iocs,omitempty" gorm:"foreignKey:ReportID"`
}

// ReportIOC model (junction table)
type ReportIOC struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	ReportID  uint      `json:"report_id" gorm:"not null"`
	IOCID     uint      `json:"ioc_id" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`

	// Relationships
	Report Report `json:"report" gorm:"foreignKey:ReportID"`
	IOC    IOC    `json:"ioc" gorm:"foreignKey:IOCID"`
}

// AuditLog model
type AuditLog struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	UserID       *uint     `json:"user_id"`
	Action       string    `json:"action" gorm:"size:100;not null"`
	ResourceType string    `json:"resource_type" gorm:"size:50;not null"`
	ResourceID   *uint     `json:"resource_id"`
	OldValues    JSON      `json:"old_values" gorm:"type:json"`
	NewValues    JSON      `json:"new_values" gorm:"type:json"`
	IPAddress    string    `json:"ip_address" gorm:"size:45"`
	UserAgent    string    `json:"user_agent" gorm:"type:text"`
	CreatedAt    time.Time `json:"created_at"`

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// APIKey model
type APIKey struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Name        string    `json:"name" gorm:"size:100;not null"`
	KeyHash     string    `json:"key_hash" gorm:"size:255;not null"`
	Permissions JSON      `json:"permissions" gorm:"type:json"`
	LastUsed    *time.Time `json:"last_used"`
	ExpiresAt   *time.Time `json:"expires_at"`
	IsActive    bool      `json:"is_active" gorm:"default:true"`
	CreatedBy   uint      `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relationships
	Creator User `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
}

// Session model
type Session struct {
	ID        string    `json:"id" gorm:"primaryKey;size:128"`
	UserID    uint      `json:"user_id" gorm:"not null"`
	IPAddress string    `json:"ip_address" gorm:"size:45"`
	UserAgent string    `json:"user_agent" gorm:"type:text"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`

	// Relationships
	User User `json:"user" gorm:"foreignKey:UserID"`
}

// Activity model (for tracking threat activities and timeline events)
type Activity struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	CampaignID      *uint     `json:"campaign_id"`
	ThreatActorID   *uint     `json:"threat_actor_id"`
	Name            string    `json:"name" gorm:"size:200;not null"`
	Description     string    `json:"description" gorm:"type:text"`
	ActivityType    string    `json:"activity_type" gorm:"type:enum('reconnaissance','initial_access','execution','persistence','privilege_escalation','defense_evasion','credential_access','discovery','lateral_movement','collection','command_control','exfiltration','impact','other');default:'other'"`
	Phase           string    `json:"phase" gorm:"type:enum('preparation','initial_compromise','establish_foothold','escalate_privileges','internal_reconnaissance','move_laterally','maintain_presence','complete_mission');default:'preparation'"`
	Status          string    `json:"status" gorm:"type:enum('planned','in_progress','completed','failed','cancelled');default:'planned'"`
	Severity        string    `json:"severity" gorm:"type:enum('low','medium','high','critical');default:'medium'"`
	StartTime       *time.Time `json:"start_time"`
	EndTime         *time.Time `json:"end_time"`
	Location        string    `json:"location" gorm:"size:100"`
	TargetSectors   JSON      `json:"target_sectors" gorm:"type:json"`
	TargetCountries JSON      `json:"target_countries" gorm:"type:json"`
	TechniquesUsed  JSON      `json:"techniques_used" gorm:"type:json"` // MITRE ATT&CK techniques
	ToolsUsed       JSON      `json:"tools_used" gorm:"type:json"`
	VictimsAffected int       `json:"victims_affected" gorm:"default:0"`
	ConfidenceLevel int       `json:"confidence_level" gorm:"default:50;check:confidence_level >= 0 AND confidence_level <= 100"`
	Source          string    `json:"source" gorm:"size:100"`
	CreatedBy       uint      `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	// Relationships
	Campaign      *Campaign       `json:"campaign,omitempty" gorm:"foreignKey:CampaignID"`
	ThreatActor   *ThreatActor    `json:"threat_actor,omitempty" gorm:"foreignKey:ThreatActorID"`
	Creator       User            `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
	ActivityIOCs  []ActivityIOC   `json:"activity_iocs,omitempty" gorm:"foreignKey:ActivityID"`
}

// CampaignActor model (junction table for many-to-many relationship)
type CampaignActor struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	CampaignID    uint      `json:"campaign_id" gorm:"not null"`
	ThreatActorID uint      `json:"threat_actor_id" gorm:"not null"`
	Role          string    `json:"role" gorm:"type:enum('primary','secondary','collaborator','sponsor','unknown');default:'unknown'"`
	ConfidenceLevel int     `json:"confidence_level" gorm:"default:50;check:confidence_level >= 0 AND confidence_level <= 100"`
	FirstSeen     *time.Time `json:"first_seen"`
	LastSeen      *time.Time `json:"last_seen"`
	CreatedAt     time.Time `json:"created_at"`

	// Relationships
	Campaign    Campaign    `json:"campaign" gorm:"foreignKey:CampaignID"`
	ThreatActor ThreatActor `json:"threat_actor" gorm:"foreignKey:ThreatActorID"`
}

// ActivityIOC model (junction table for activity-IOC relationships)
type ActivityIOC struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	ActivityID   uint      `json:"activity_id" gorm:"not null"`
	IOCID        uint      `json:"ioc_id" gorm:"not null"`
	Relationship string    `json:"relationship" gorm:"type:enum('used_in','detected_in','attributed_to','related_to');default:'related_to'"`
	ConfidenceLevel int    `json:"confidence_level" gorm:"default:50;check:confidence_level >= 0 AND confidence_level <= 100"`
	CreatedAt    time.Time `json:"created_at"`

	// Relationships
	Activity Activity `json:"activity" gorm:"foreignKey:ActivityID"`
	IOC      IOC      `json:"ioc" gorm:"foreignKey:IOCID"`
}

// Notification model
type Notification struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	UserID    *uint     `json:"user_id"`
	Title     string    `json:"title" gorm:"size:200;not null"`
	Message   string    `json:"message" gorm:"type:text"`
	Type      string    `json:"type" gorm:"type:enum('info','warning','error','success');default:'info'"`
	IsRead    bool      `json:"is_read" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at"`

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// SystemSetting model for global system configuration
type SystemSetting struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Key         string    `json:"key" gorm:"uniqueIndex;size:100;not null"`
	Value       string    `json:"value" gorm:"type:text"`
	Category    string    `json:"category" gorm:"size:50;not null"`
	Description string    `json:"description" gorm:"type:text"`
	DataType    string    `json:"data_type" gorm:"type:enum('string','integer','boolean','json','float');default:'string'"`
	IsPublic    bool      `json:"is_public" gorm:"default:false"` // Whether setting can be read by non-admin users
	CreatedBy   uint      `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relationships
	Creator User `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
}

// UserSetting model for user-specific preferences
type UserSetting struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	UserID    uint      `json:"user_id" gorm:"not null"`
	Key       string    `json:"key" gorm:"size:100;not null"`
	Value     string    `json:"value" gorm:"type:text"`
	Category  string    `json:"category" gorm:"size:50;not null"`
	DataType  string    `json:"data_type" gorm:"type:enum('string','integer','boolean','json','float');default:'string'"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	User User `json:"user" gorm:"foreignKey:UserID"`
}

// SecurityPolicy model for security configuration
type SecurityPolicy struct {
	ID                    uint      `json:"id" gorm:"primaryKey"`
	Name                  string    `json:"name" gorm:"size:100;not null"`
	Description           string    `json:"description" gorm:"type:text"`
	PasswordMinLength     int       `json:"password_min_length" gorm:"default:8"`
	PasswordRequireUpper  bool      `json:"password_require_upper" gorm:"default:true"`
	PasswordRequireLower  bool      `json:"password_require_lower" gorm:"default:true"`
	PasswordRequireNumber bool      `json:"password_require_number" gorm:"default:true"`
	PasswordRequireSymbol bool      `json:"password_require_symbol" gorm:"default:true"`
	SessionTimeout        int       `json:"session_timeout" gorm:"default:3600"` // seconds
	MaxLoginAttempts      int       `json:"max_login_attempts" gorm:"default:5"`
	LockoutDuration       int       `json:"lockout_duration" gorm:"default:900"` // seconds
	TwoFactorRequired     bool      `json:"two_factor_required" gorm:"default:false"`
	IPWhitelist           JSON      `json:"ip_whitelist" gorm:"type:json"`
	IsActive              bool      `json:"is_active" gorm:"default:true"`
	CreatedBy             uint      `json:"created_by"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`

	// Relationships
	Creator User `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
}

// BackupConfiguration model for backup settings
type BackupConfiguration struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	Name            string    `json:"name" gorm:"size:100;not null"`
	BackupType      string    `json:"backup_type" gorm:"type:enum('full','incremental','differential');default:'full'"`
	Schedule        string    `json:"schedule" gorm:"size:100"` // Cron expression
	RetentionDays   int       `json:"retention_days" gorm:"default:30"`
	StorageLocation string    `json:"storage_location" gorm:"type:text"`
	EncryptionKey   string    `json:"encryption_key" gorm:"size:255"`
	IsEnabled       bool      `json:"is_enabled" gorm:"default:true"`
	LastBackup      *time.Time `json:"last_backup"`
	NextBackup      *time.Time `json:"next_backup"`
	CreatedBy       uint      `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	// Relationships
	Creator User `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
}
