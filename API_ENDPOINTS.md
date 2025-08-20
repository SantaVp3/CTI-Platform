# CTI Platform API Endpoints

## Authentication
All endpoints require authentication via JWT token in the Authorization header:
```
Authorization: Bearer <jwt_token>
```

## Campaign Management

### Campaigns
- `GET /api/campaigns` - List campaigns with filtering and pagination
- `POST /api/campaigns` - Create new campaign
- `GET /api/campaigns/:id` - Get campaign details
- `PUT /api/campaigns/:id` - Update campaign
- `DELETE /api/campaigns/:id` - Delete campaign
- `GET /api/campaigns/statistics` - Get campaign statistics

### Campaign-Actor Associations
- `POST /api/campaigns/:id/actors` - Associate threat actor with campaign
- `DELETE /api/campaigns/:id/actors/:actor_id` - Remove actor association

## Threat Feed Management

### Threat Feeds
- `GET /api/threat-feeds` - List threat feeds with filtering
- `POST /api/threat-feeds` - Create new threat feed
- `GET /api/threat-feeds/:id` - Get feed details
- `PUT /api/threat-feeds/:id` - Update feed configuration
- `DELETE /api/threat-feeds/:id` - Delete threat feed
- `POST /api/threat-feeds/:id/ingest` - Trigger manual ingestion

### Feed Configuration
- `GET /api/threat-feeds/types` - Get available feed types
- `GET /api/threat-feeds/auth-types` - Get authentication types
- `POST /api/threat-feeds/test` - Test feed connection
- `GET /api/threat-feeds/statistics` - Get feed statistics
- `GET /api/threat-feeds/:id/logs` - Get ingestion logs

## Report Management

### Reports
- `GET /api/reports` - List reports with filtering
- `POST /api/reports` - Create new report
- `GET /api/reports/:id` - Get report details
- `PUT /api/reports/:id` - Update report
- `DELETE /api/reports/:id` - Delete report
- `POST /api/reports/:id/publish` - Publish report

### Report Configuration
- `GET /api/reports/types` - Get report types
- `GET /api/reports/tlp-levels` - Get TLP classification levels
- `GET /api/reports/template?type=<type>` - Generate report template
- `GET /api/reports/statistics` - Get report statistics
- `GET /api/reports/:id/export/json` - Export report as JSON

## IOC Management

### IOCs
- `GET /api/iocs` - List IOCs with filtering and search
- `POST /api/iocs` - Create new IOC
- `GET /api/iocs/:id` - Get IOC details
- `PUT /api/iocs/:id` - Update IOC
- `DELETE /api/iocs/:id` - Delete IOC
- `POST /api/iocs/bulk-import` - Bulk import IOCs
- `GET /api/iocs/export` - Export IOCs

### IOC Analysis
- `POST /api/iocs/:id/analyze` - Analyze IOC
- `GET /api/iocs/:id/analysis` - Get analysis results

## Threat Actor Management

### Threat Actors
- `GET /api/threat-actors` - List threat actors
- `POST /api/threat-actors` - Create new threat actor
- `GET /api/threat-actors/:id` - Get actor details
- `PUT /api/threat-actors/:id` - Update actor
- `DELETE /api/threat-actors/:id` - Delete actor

## Dashboard & Statistics

### Dashboard
- `GET /api/dashboard/stats` - Get dashboard statistics
- `GET /api/dashboard/recent-activity` - Get recent activity

## User Management

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `POST /api/auth/refresh` - Refresh JWT token

### Users
- `GET /api/users` - List users (admin only)
- `POST /api/users` - Create user (admin only)
- `GET /api/users/:id` - Get user details
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user (admin only)

## Request/Response Formats

### Standard Response Format
```json
{
  "data": <response_data>,
  "message": "Success message",
  "total": <total_count_for_lists>,
  "page": <current_page>,
  "limit": <items_per_page>
}
```

### Error Response Format
```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": <additional_error_details>
}
```

### Pagination Parameters
- `page` - Page number (default: 1)
- `limit` - Items per page (default: 20, max: 100)

### Common Filters
- `search` - Text search across relevant fields
- `created_by` - Filter by creator user ID
- `created_at_from` - Filter by creation date (from)
- `created_at_to` - Filter by creation date (to)

## Status Codes

- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `422` - Unprocessable Entity
- `500` - Internal Server Error

## Rate Limiting

API endpoints are rate limited to prevent abuse:
- Authenticated users: 1000 requests per hour
- Unauthenticated endpoints: 100 requests per hour

## Data Models

### Campaign
```json
{
  "id": 1,
  "name": "Campaign Name",
  "description": "Campaign description",
  "status": "active|planning|dormant|completed",
  "sophistication": "basic|intermediate|advanced|expert|innovator",
  "impact": "low|medium|high|critical",
  "scope": "local|regional|national|global",
  "start_date": "2024-01-01T00:00:00Z",
  "end_date": "2024-12-31T23:59:59Z",
  "threat_actor_id": 1,
  "created_by": 1,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

### Threat Feed
```json
{
  "id": 1,
  "name": "Feed Name",
  "description": "Feed description",
  "url": "https://example.com/feed",
  "feed_type": "json|stix|taxii|csv|xml|rss",
  "authentication_type": "none|basic|api_key|oauth",
  "update_frequency": 3600,
  "is_active": true,
  "last_update": "2024-01-01T00:00:00Z",
  "next_update": "2024-01-01T01:00:00Z",
  "created_by": 1,
  "created_at": "2024-01-01T00:00:00Z"
}
```

### Report
```json
{
  "id": 1,
  "title": "Report Title",
  "description": "Report description",
  "content": "Report content in markdown",
  "report_type": "incident|threat_analysis|ioc_analysis|campaign_analysis|actor_profile|custom",
  "status": "draft|review|published|archived",
  "tlp": "white|green|amber|red",
  "created_by": 1,
  "published_at": "2024-01-01T00:00:00Z",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```
