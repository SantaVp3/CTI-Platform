-- CTI Platform Complete Database Schema
-- Consolidated schema file for the Cyber Threat Intelligence Platform
-- This file contains all table definitions and essential data

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS cti_platform;
USE cti_platform;

-- Users table for authentication and authorization
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    role ENUM('admin', 'analyst', 'viewer') DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_role (role),
    INDEX idx_active (is_active)
);

-- Threat actors table
CREATE TABLE threat_actors (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    aliases JSON,
    description TEXT,
    country VARCHAR(2), -- ISO country code
    motivation ENUM('financial', 'espionage', 'hacktivism', 'warfare', 'unknown') DEFAULT 'unknown',
    sophistication ENUM('minimal', 'intermediate', 'advanced', 'expert', 'innovator') DEFAULT 'unknown',
    resource_level ENUM('individual', 'club', 'contest', 'team', 'organization', 'government') DEFAULT 'unknown',
    first_seen DATE,
    last_seen DATE,
    is_active BOOLEAN DEFAULT TRUE,
    confidence_level INT DEFAULT 50 CHECK (confidence_level >= 0 AND confidence_level <= 100),
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (created_by) REFERENCES users(id),
    INDEX idx_name (name),
    INDEX idx_country (country),
    INDEX idx_motivation (motivation),
    INDEX idx_active (is_active),
    INDEX idx_first_seen (first_seen),
    INDEX idx_last_seen (last_seen)
);

-- Campaigns table (enhanced with additional fields)
CREATE TABLE campaigns (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    aliases JSON,
    description TEXT,
    objectives JSON,
    threat_actor_id INT,
    start_date DATE,
    end_date DATE,
    status ENUM('planning','active','dormant','completed','unknown') DEFAULT 'unknown',
    sophistication ENUM('minimal','intermediate','advanced','expert','innovator','unknown') DEFAULT 'unknown',
    scope ENUM('individual','organization','sector','regional','global','unknown') DEFAULT 'unknown',
    impact ENUM('low','medium','high','critical','unknown') DEFAULT 'unknown',
    ttp JSON,
    target_sectors JSON,
    target_countries JSON,
    is_active BOOLEAN DEFAULT TRUE,
    confidence_level INT DEFAULT 50 CHECK (confidence_level >= 0 AND confidence_level <= 100),
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (threat_actor_id) REFERENCES threat_actors(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id),
    INDEX idx_name (name),
    INDEX idx_threat_actor (threat_actor_id),
    INDEX idx_start_date (start_date),
    INDEX idx_end_date (end_date),
    INDEX idx_active (is_active),
    INDEX idx_status (status),
    INDEX idx_sophistication (sophistication),
    INDEX idx_scope (scope),
    INDEX idx_impact (impact)
);

-- IOC types table
CREATE TABLE ioc_types (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    pattern_regex VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default IOC types (essential data)
INSERT INTO ioc_types (name, description, pattern_regex) VALUES
('ip', 'IP Address', '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
('domain', 'Domain Name', '^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}$'),
('url', 'URL', '^https?://[^\\s/$.?#].[^\\s]*$'),
('md5', 'MD5 Hash', '^[a-fA-F0-9]{32}$'),
('sha1', 'SHA1 Hash', '^[a-fA-F0-9]{40}$'),
('sha256', 'SHA256 Hash', '^[a-fA-F0-9]{64}$'),
('email', 'Email Address', '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'),
('filename', 'File Name', '.*'),
('registry_key', 'Registry Key', '^HKEY_.*'),
('mutex', 'Mutex', '.*'),
('user_agent', 'User Agent', '.*'),
('asn', 'ASN', '^AS[0-9]+$'),
('cve', 'CVE', '^CVE-[0-9]{4}-[0-9]{4,}$');

-- IOCs (Indicators of Compromise) table
CREATE TABLE iocs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    value VARCHAR(500) NOT NULL,
    type_id INT NOT NULL,
    threat_actor_id INT,
    campaign_id INT,
    description TEXT,
    tags JSON,
    tlp ENUM('white', 'green', 'amber', 'red') DEFAULT 'white',
    confidence_level INT DEFAULT 50 CHECK (confidence_level >= 0 AND confidence_level <= 100),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expiration_date TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    false_positive BOOLEAN DEFAULT FALSE,
    source VARCHAR(100),
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (type_id) REFERENCES ioc_types(id),
    FOREIGN KEY (threat_actor_id) REFERENCES threat_actors(id) ON DELETE SET NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id),
    UNIQUE KEY unique_ioc_type (value, type_id),
    INDEX idx_value (value),
    INDEX idx_type (type_id),
    INDEX idx_threat_actor (threat_actor_id),
    INDEX idx_campaign (campaign_id),
    INDEX idx_tlp (tlp),
    INDEX idx_severity (severity),
    INDEX idx_first_seen (first_seen),
    INDEX idx_last_seen (last_seen),
    INDEX idx_active (is_active),
    INDEX idx_false_positive (false_positive),
    INDEX idx_source (source)
);

-- Activities table for tracking threat activities and timeline events
CREATE TABLE activities (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    campaign_id BIGINT UNSIGNED NULL,
    threat_actor_id BIGINT UNSIGNED NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    activity_type ENUM(
        'reconnaissance',
        'initial_access',
        'execution',
        'persistence',
        'privilege_escalation',
        'defense_evasion',
        'credential_access',
        'discovery',
        'lateral_movement',
        'collection',
        'command_control',
        'exfiltration',
        'impact',
        'other'
    ) DEFAULT 'other',
    phase ENUM(
        'preparation',
        'initial_compromise',
        'establish_foothold',
        'escalate_privileges',
        'internal_reconnaissance',
        'move_laterally',
        'maintain_presence',
        'complete_mission'
    ) DEFAULT 'preparation',
    status ENUM('planned','in_progress','completed','failed','cancelled') DEFAULT 'planned',
    severity ENUM('low','medium','high','critical') DEFAULT 'medium',
    start_time DATETIME NULL,
    end_time DATETIME NULL,
    location VARCHAR(100),
    target_sectors JSON,
    target_countries JSON,
    techniques_used JSON,
    tools_used JSON,
    victims_affected INT DEFAULT 0,
    confidence_level INT DEFAULT 50 CHECK (confidence_level >= 0 AND confidence_level <= 100),
    source VARCHAR(100),
    created_by BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE SET NULL,
    FOREIGN KEY (threat_actor_id) REFERENCES threat_actors(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT,

    INDEX idx_activities_campaign_id (campaign_id),
    INDEX idx_activities_threat_actor_id (threat_actor_id),
    INDEX idx_activities_activity_type (activity_type),
    INDEX idx_activities_phase (phase),
    INDEX idx_activities_status (status),
    INDEX idx_activities_severity (severity),
    INDEX idx_activities_start_time (start_time),
    INDEX idx_activities_end_time (end_time),
    INDEX idx_activities_created_by (created_by),
    INDEX idx_activities_created_at (created_at)
);

-- Campaign-actors junction table for many-to-many relationship
CREATE TABLE campaign_actors (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    campaign_id BIGINT UNSIGNED NOT NULL,
    threat_actor_id BIGINT UNSIGNED NOT NULL,
    role ENUM('primary','secondary','collaborator','sponsor','unknown') DEFAULT 'unknown',
    confidence_level INT DEFAULT 50 CHECK (confidence_level >= 0 AND confidence_level <= 100),
    first_seen DATE NULL,
    last_seen DATE NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
    FOREIGN KEY (threat_actor_id) REFERENCES threat_actors(id) ON DELETE CASCADE,

    UNIQUE KEY unique_campaign_actor (campaign_id, threat_actor_id),

    INDEX idx_campaign_actors_campaign_id (campaign_id),
    INDEX idx_campaign_actors_threat_actor_id (threat_actor_id),
    INDEX idx_campaign_actors_role (role)
);

-- Activity-IOCs junction table for activity-IOC relationships
CREATE TABLE activity_iocs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    activity_id BIGINT UNSIGNED NOT NULL,
    ioc_id BIGINT UNSIGNED NOT NULL,
    relationship ENUM('used_in','detected_in','attributed_to','related_to') DEFAULT 'related_to',
    confidence_level INT DEFAULT 50 CHECK (confidence_level >= 0 AND confidence_level <= 100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE CASCADE,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,

    UNIQUE KEY unique_activity_ioc (activity_id, ioc_id),

    INDEX idx_activity_iocs_activity_id (activity_id),
    INDEX idx_activity_iocs_ioc_id (ioc_id),
    INDEX idx_activity_iocs_relationship (relationship)
);

-- Threat feeds table
CREATE TABLE threat_feeds (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    url VARCHAR(500),
    feed_type ENUM('stix', 'taxii', 'json', 'csv', 'xml', 'rss') DEFAULT 'json',
    authentication_type ENUM('none', 'basic', 'api_key', 'oauth') DEFAULT 'none',
    credentials JSON, -- Encrypted credentials
    update_frequency INT DEFAULT 3600, -- seconds
    last_update TIMESTAMP NULL,
    next_update TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (created_by) REFERENCES users(id),
    INDEX idx_name (name),
    INDEX idx_feed_type (feed_type),
    INDEX idx_last_update (last_update),
    INDEX idx_next_update (next_update),
    INDEX idx_active (is_active)
);

-- Feed ingestion logs
CREATE TABLE feed_ingestion_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    feed_id INT NOT NULL,
    status ENUM('success', 'error', 'partial') NOT NULL,
    records_processed INT DEFAULT 0,
    records_added INT DEFAULT 0,
    records_updated INT DEFAULT 0,
    error_message TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,

    FOREIGN KEY (feed_id) REFERENCES threat_feeds(id) ON DELETE CASCADE,
    INDEX idx_feed_id (feed_id),
    INDEX idx_status (status),
    INDEX idx_started_at (started_at)
);

-- Analysis results table
CREATE TABLE analysis_results (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ioc_id INT NOT NULL,
    analysis_type ENUM('reputation', 'enrichment', 'sandbox', 'static', 'dynamic') NOT NULL,
    analyzer VARCHAR(100) NOT NULL, -- e.g., 'virustotal', 'shodan', 'cuckoo'
    result JSON NOT NULL,
    score INT CHECK (score >= 0 AND score <= 100),
    verdict ENUM('clean', 'suspicious', 'malicious', 'unknown') DEFAULT 'unknown',
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,

    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
    INDEX idx_ioc_id (ioc_id),
    INDEX idx_analysis_type (analysis_type),
    INDEX idx_analyzer (analyzer),
    INDEX idx_verdict (verdict),
    INDEX idx_analyzed_at (analyzed_at),
    INDEX idx_expires_at (expires_at)
);

-- STIX objects table for STIX/TAXII compliance
CREATE TABLE stix_objects (
    id INT PRIMARY KEY AUTO_INCREMENT,
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    stix_type VARCHAR(50) NOT NULL,
    spec_version VARCHAR(10) DEFAULT '2.1',
    object_data JSON NOT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,

    INDEX idx_stix_id (stix_id),
    INDEX idx_stix_type (stix_type),
    INDEX idx_created (created),
    INDEX idx_modified (modified),
    INDEX idx_revoked (revoked)
);

-- Reports table
CREATE TABLE reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    content LONGTEXT,
    report_type ENUM('incident', 'campaign', 'actor', 'ioc', 'custom') DEFAULT 'custom',
    status ENUM('draft', 'review', 'published', 'archived') DEFAULT 'draft',
    tlp ENUM('white', 'green', 'amber', 'red') DEFAULT 'white',
    created_by INT,
    published_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (created_by) REFERENCES users(id),
    INDEX idx_title (title),
    INDEX idx_report_type (report_type),
    INDEX idx_status (status),
    INDEX idx_tlp (tlp),
    INDEX idx_published_at (published_at),
    INDEX idx_created_at (created_at)
);

-- Report IOC associations
CREATE TABLE report_iocs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    report_id INT NOT NULL,
    ioc_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
    UNIQUE KEY unique_report_ioc (report_id, ioc_id),
    INDEX idx_report_id (report_id),
    INDEX idx_ioc_id (ioc_id)
);

-- Audit logs table
CREATE TABLE audit_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id INT,
    old_values JSON,
    new_values JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_resource_type (resource_type),
    INDEX idx_resource_id (resource_id),
    INDEX idx_created_at (created_at)
);

-- API keys table for external integrations
CREATE TABLE api_keys (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    permissions JSON,
    last_used TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (created_by) REFERENCES users(id),
    INDEX idx_key_hash (key_hash),
    INDEX idx_last_used (last_used),
    INDEX idx_expires_at (expires_at),
    INDEX idx_active (is_active)
);

-- Sessions table for user session management
CREATE TABLE sessions (
    id VARCHAR(128) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
);

-- Notifications table
CREATE TABLE notifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    title VARCHAR(200) NOT NULL,
    message TEXT,
    type ENUM('info', 'warning', 'error', 'success') DEFAULT 'info',
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_type (type),
    INDEX idx_is_read (is_read),
    INDEX idx_created_at (created_at)
);

-- System settings table
CREATE TABLE system_settings (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `key` VARCHAR(100) NOT NULL,
    value TEXT,
    category VARCHAR(50) NOT NULL,
    description TEXT,
    data_type ENUM('string','integer','boolean','json','float') DEFAULT 'string',
    is_public BOOLEAN DEFAULT FALSE,
    created_by BIGINT UNSIGNED,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE INDEX idx_system_settings_key (`key`),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- User settings table
CREATE TABLE user_settings (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    `key` VARCHAR(100) NOT NULL,
    value TEXT,
    category VARCHAR(50) NOT NULL,
    data_type ENUM('string','integer','boolean','json','float') DEFAULT 'string',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Security policies table
CREATE TABLE security_policies (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    password_min_length BIGINT DEFAULT 8,
    password_require_upper BOOLEAN DEFAULT TRUE,
    password_require_lower BOOLEAN DEFAULT TRUE,
    password_require_number BOOLEAN DEFAULT TRUE,
    password_require_symbol BOOLEAN DEFAULT TRUE,
    session_timeout BIGINT DEFAULT 3600,
    max_login_attempts BIGINT DEFAULT 5,
    lockout_duration BIGINT DEFAULT 900,
    two_factor_required BOOLEAN DEFAULT FALSE,
    ip_whitelist JSON,
    is_active BOOLEAN DEFAULT TRUE,
    created_by BIGINT UNSIGNED,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Backup configurations table
CREATE TABLE backup_configurations (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    backup_type ENUM('full','incremental','differential') DEFAULT 'full',
    schedule VARCHAR(100),
    retention_days BIGINT DEFAULT 30,
    storage_location TEXT,
    encryption_key VARCHAR(255),
    is_enabled BOOLEAN DEFAULT TRUE,
    last_backup TIMESTAMP NULL,
    next_backup TIMESTAMP NULL,
    created_by BIGINT UNSIGNED,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Create default admin user (password: admin123)
-- Note: In production, this should be changed immediately
INSERT INTO users (username, email, password_hash, first_name, last_name, role, is_active) VALUES
('admin', 'admin@cti-platform.com', '$2a$10$c6qzni/2IhBCZepV6ZyM8uOyagWQMCuMjzoNjfPo0kuvZTtPFmqo2', 'System', 'Administrator', 'admin', TRUE);

-- IOCs (Indicators of Compromise) table
CREATE TABLE iocs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    value VARCHAR(500) NOT NULL,
    type_id INT NOT NULL,
    threat_actor_id INT,
    campaign_id INT,
    description TEXT,
    tags JSON,
    tlp ENUM('white', 'green', 'amber', 'red') DEFAULT 'white',
    confidence_level INT DEFAULT 50 CHECK (confidence_level >= 0 AND confidence_level <= 100),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expiration_date TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    false_positive BOOLEAN DEFAULT FALSE,
    source VARCHAR(100),
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (type_id) REFERENCES ioc_types(id),
    FOREIGN KEY (threat_actor_id) REFERENCES threat_actors(id) ON DELETE SET NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id),
    UNIQUE KEY unique_ioc_type (value, type_id),
    INDEX idx_value (value),
    INDEX idx_type (type_id),
    INDEX idx_threat_actor (threat_actor_id),
    INDEX idx_campaign (campaign_id),
    INDEX idx_tlp (tlp),
    INDEX idx_severity (severity),
    INDEX idx_first_seen (first_seen),
    INDEX idx_last_seen (last_seen),
    INDEX idx_active (is_active),
    INDEX idx_false_positive (false_positive),
    INDEX idx_source (source)
);

-- Activities table for tracking threat activities and timeline events
CREATE TABLE activities (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    campaign_id BIGINT UNSIGNED NULL,
    threat_actor_id BIGINT UNSIGNED NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    activity_type ENUM(
        'reconnaissance',
        'initial_access',
        'execution',
        'persistence',
        'privilege_escalation',
        'defense_evasion',
        'credential_access',
        'discovery',
        'lateral_movement',
        'collection',
        'command_control',
        'exfiltration',
        'impact',
        'other'
    ) DEFAULT 'other',
    phase ENUM(
        'preparation',
        'initial_compromise',
        'establish_foothold',
        'escalate_privileges',
        'internal_reconnaissance',
        'move_laterally',
        'maintain_presence',
        'complete_mission'
    ) DEFAULT 'preparation',
    status ENUM('planned','in_progress','completed','failed','cancelled') DEFAULT 'planned',
    severity ENUM('low','medium','high','critical') DEFAULT 'medium',
    start_time DATETIME NULL,
    end_time DATETIME NULL,
    location VARCHAR(100),
    target_sectors JSON,
    target_countries JSON,
    techniques_used JSON,
    tools_used JSON,
    victims_affected INT DEFAULT 0,
    confidence_level INT DEFAULT 50 CHECK (confidence_level >= 0 AND confidence_level <= 100),
    source VARCHAR(100),
    created_by BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE SET NULL,
    FOREIGN KEY (threat_actor_id) REFERENCES threat_actors(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT,

    INDEX idx_activities_campaign_id (campaign_id),
    INDEX idx_activities_threat_actor_id (threat_actor_id),
    INDEX idx_activities_activity_type (activity_type),
    INDEX idx_activities_phase (phase),
    INDEX idx_activities_status (status),
    INDEX idx_activities_severity (severity),
    INDEX idx_activities_start_time (start_time),
    INDEX idx_activities_end_time (end_time),
    INDEX idx_activities_created_by (created_by),
    INDEX idx_activities_created_at (created_at)
);
