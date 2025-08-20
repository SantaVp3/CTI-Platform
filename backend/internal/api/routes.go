package api

import (
	"cti-platform/internal/api/handlers"
	"cti-platform/internal/middleware"
	"cti-platform/internal/services"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine, services *services.Services) {
	// Initialize handlers
	authHandler := handlers.NewAuthHandler(services.Auth)
	userHandler := handlers.NewUserHandler(services.User)
	iocHandler := handlers.NewIOCHandler(services.IOC)
	threatActorHandler := handlers.NewThreatActorHandler(services.ThreatActor)
	campaignHandler := handlers.NewCampaignHandler(services.Campaign)
	activityHandler := handlers.NewActivityHandler(services.Activity)
	threatFeedHandler := handlers.NewThreatFeedHandler(services.ThreatFeed)
	analysisHandler := handlers.NewAnalysisHandler(services.Analysis)
	reportHandler := handlers.NewReportHandler(services.Report)
	stixHandler := handlers.NewSTIXHandler(services.STIX)
	notificationHandler := handlers.NewNotificationHandler(services.Notification)
	dashboardHandler := handlers.NewDashboardHandler(services)
	settingsHandler := handlers.NewSettingsHandler(services.Settings)

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "cti-platform-api",
		})
	})

	// API version 1
	v1 := router.Group("/api/v1")

	// Public routes (no authentication required)
	public := v1.Group("/")
	{
		public.POST("/auth/login", authHandler.Login)
		public.POST("/auth/refresh", authHandler.RefreshToken)
	}

	// Protected routes (authentication required)
	protected := v1.Group("/")
	protected.Use(middleware.Auth(services.Auth))
	protected.Use(middleware.AuditLog(services.Audit))
	{
		// Authentication routes
		auth := protected.Group("/auth")
		{
			auth.POST("/logout", authHandler.Logout)
			auth.GET("/me", authHandler.GetCurrentUser)
		}

		// User management routes
		users := protected.Group("/users")
		{
			users.GET("/", middleware.RequireRole("admin"), userHandler.GetUsers)
			users.POST("/", middleware.RequireRole("admin"), userHandler.CreateUser)
			users.GET("/:id", middleware.RequireRole("admin", "analyst"), userHandler.GetUser)
			users.PUT("/:id", middleware.RequireRole("admin"), userHandler.UpdateUser)
			users.DELETE("/:id", middleware.RequireRole("admin"), userHandler.DeleteUser)
		}

		// IOC routes
		iocs := protected.Group("/iocs")
		{
			iocs.GET("/", iocHandler.SearchIOCs)
			iocs.POST("/", middleware.RequireRole("admin", "analyst"), iocHandler.CreateIOC)
			iocs.GET("/types", iocHandler.GetIOCTypes)
			iocs.GET("/:id", iocHandler.GetIOC)
			iocs.PUT("/:id", middleware.RequireRole("admin", "analyst"), iocHandler.UpdateIOC)
			iocs.DELETE("/:id", middleware.RequireRole("admin", "analyst"), iocHandler.DeleteIOC)
			iocs.POST("/:id/analyze", middleware.RequireRole("admin", "analyst"), analysisHandler.AnalyzeIOC)
		}

		// Threat Actor routes
		threatActors := protected.Group("/threat-actors")
		{
			threatActors.GET("/", threatActorHandler.SearchThreatActors)
			threatActors.POST("/", middleware.RequireRole("admin", "analyst"), threatActorHandler.CreateThreatActor)
			threatActors.GET("/:id", threatActorHandler.GetThreatActor)
			threatActors.PUT("/:id", middleware.RequireRole("admin", "analyst"), threatActorHandler.UpdateThreatActor)
			threatActors.DELETE("/:id", middleware.RequireRole("admin", "analyst"), threatActorHandler.DeleteThreatActor)
		}

		// Campaign routes
		campaigns := protected.Group("/campaigns")
		{
			campaigns.GET("/", campaignHandler.SearchCampaigns)
			campaigns.POST("/", middleware.RequireRole("admin", "analyst"), campaignHandler.CreateCampaign)
			campaigns.GET("/statistics", campaignHandler.GetCampaignStatistics)
			campaigns.GET("/statuses", campaignHandler.GetCampaignStatuses)
			campaigns.GET("/sophistications", campaignHandler.GetCampaignSophistications)
			campaigns.GET("/scopes", campaignHandler.GetCampaignScopes)
			campaigns.GET("/impacts", campaignHandler.GetCampaignImpacts)
			campaigns.GET("/actor-roles", campaignHandler.GetCampaignActorRoles)
			campaigns.GET("/:id", campaignHandler.GetCampaign)
			campaigns.PUT("/:id", middleware.RequireRole("admin", "analyst"), campaignHandler.UpdateCampaign)
			campaigns.DELETE("/:id", middleware.RequireRole("admin", "analyst"), campaignHandler.DeleteCampaign)
			campaigns.POST("/:id/actors", middleware.RequireRole("admin", "analyst"), campaignHandler.AddThreatActorToCampaign)
			campaigns.DELETE("/:id/actors/:actor_id", middleware.RequireRole("admin", "analyst"), campaignHandler.RemoveThreatActorFromCampaign)
		}

		// Activity routes
		activities := protected.Group("/activities")
		{
			activities.GET("/", activityHandler.GetActivities)
			activities.POST("/", middleware.RequireRole("admin", "analyst"), activityHandler.CreateActivity)
			activities.GET("/timeline", activityHandler.GetActivityTimeline)
			activities.GET("/types", activityHandler.GetActivityTypes)
			activities.GET("/phases", activityHandler.GetActivityPhases)
			activities.GET("/statuses", activityHandler.GetActivityStatuses)
			activities.GET("/severities", activityHandler.GetActivitySeverities)
			activities.GET("/:id", activityHandler.GetActivityByID)
			activities.PUT("/:id", middleware.RequireRole("admin", "analyst"), activityHandler.UpdateActivity)
			activities.DELETE("/:id", middleware.RequireRole("admin", "analyst"), activityHandler.DeleteActivity)
		}

		// Threat Feed routes
		threatFeeds := protected.Group("/threat-feeds")
		{
			threatFeeds.GET("/", threatFeedHandler.GetThreatFeeds)
			threatFeeds.POST("/", middleware.RequireRole("admin", "analyst"), threatFeedHandler.CreateThreatFeed)
			threatFeeds.GET("/statistics", threatFeedHandler.GetThreatFeedStatistics)
			threatFeeds.GET("/types", threatFeedHandler.GetThreatFeedTypes)
			threatFeeds.GET("/auth-types", threatFeedHandler.GetAuthenticationTypes)
			threatFeeds.POST("/test", middleware.RequireRole("admin", "analyst"), threatFeedHandler.TestThreatFeed)
			threatFeeds.GET("/:id", threatFeedHandler.GetThreatFeed)
			threatFeeds.PUT("/:id", middleware.RequireRole("admin", "analyst"), threatFeedHandler.UpdateThreatFeed)
			threatFeeds.DELETE("/:id", middleware.RequireRole("admin", "analyst"), threatFeedHandler.DeleteThreatFeed)
			threatFeeds.POST("/:id/ingest", middleware.RequireRole("admin", "analyst"), threatFeedHandler.IngestFeed)
			threatFeeds.GET("/:id/logs", threatFeedHandler.GetIngestionLogs)
		}

		// Analysis routes
		analysis := protected.Group("/analysis")
		{
			analysis.GET("/results/:ioc_id", analysisHandler.GetAnalysisResults)
			analysis.POST("/bulk-analyze", middleware.RequireRole("admin", "analyst"), analysisHandler.BulkAnalyze)
		}

		// Report routes
		reports := protected.Group("/reports")
		{
			reports.GET("/", reportHandler.SearchReports)
			reports.POST("/", middleware.RequireRole("admin", "analyst"), reportHandler.CreateReport)
			reports.GET("/statistics", reportHandler.GetReportStatistics)
			reports.GET("/types", reportHandler.GetReportTypes)
			reports.GET("/tlp-levels", reportHandler.GetTLPLevels)
			reports.GET("/template", reportHandler.GenerateReportTemplate)
			reports.GET("/:id", reportHandler.GetReport)
			reports.PUT("/:id", middleware.RequireRole("admin", "analyst"), reportHandler.UpdateReport)
			reports.DELETE("/:id", middleware.RequireRole("admin", "analyst"), reportHandler.DeleteReport)
			reports.POST("/:id/publish", middleware.RequireRole("admin", "analyst"), reportHandler.PublishReport)
			reports.GET("/:id/export/json", reportHandler.ExportReportJSON)
		}

		// STIX/TAXII routes
		stix := protected.Group("/stix")
		{
			// STIX Objects
			stix.GET("/objects", stixHandler.GetSTIXObjects)
			stix.POST("/objects", middleware.RequireRole("admin", "analyst"), stixHandler.CreateSTIXObject)
			stix.GET("/objects/:id", stixHandler.GetSTIXObject)
			stix.GET("/objects/stix-id/:stix_id", stixHandler.GetSTIXObjectBySTIXID)
			stix.PUT("/objects/:id", middleware.RequireRole("admin", "analyst"), stixHandler.UpdateSTIXObject)
			stix.DELETE("/objects/:id", middleware.RequireRole("admin", "analyst"), stixHandler.DeleteSTIXObject)

			// STIX Bundles
			stix.POST("/bundles", middleware.RequireRole("admin", "analyst"), stixHandler.CreateSTIXBundle)
			stix.GET("/bundles/:id", stixHandler.GetSTIXBundle)

			// STIX Relationships
			stix.POST("/relationships", middleware.RequireRole("admin", "analyst"), stixHandler.CreateSTIXRelationship)

			// STIX Metadata
			stix.GET("/statistics", stixHandler.GetSTIXStatistics)
			stix.GET("/types", stixHandler.GetSTIXObjectTypes)
		}

		// Notification routes
		notifications := protected.Group("/notifications")
		{
			notifications.GET("/", notificationHandler.GetNotifications)
			notifications.PUT("/:id/read", notificationHandler.MarkAsRead)
			notifications.DELETE("/:id", notificationHandler.DeleteNotification)
		}

		// Dashboard routes
		dashboard := protected.Group("/dashboard")
		{
			dashboard.GET("/stats", dashboardHandler.GetDashboardStats)
			dashboard.GET("/recent-activity", dashboardHandler.GetRecentActivity)
			dashboard.GET("/threat-trends", dashboardHandler.GetThreatTrends)
		}

		// Settings routes
		settings := protected.Group("/settings")
		{
			// System Settings
			settings.GET("/system", settingsHandler.GetSystemSettings)
			settings.POST("/system", middleware.RequireRole("admin"), settingsHandler.CreateSystemSetting)
			settings.GET("/system/:key", settingsHandler.GetSystemSetting)
			settings.PUT("/system/:key", middleware.RequireRole("admin"), settingsHandler.UpdateSystemSetting)
			settings.DELETE("/system/:key", middleware.RequireRole("admin"), settingsHandler.DeleteSystemSetting)

			// User Settings
			settings.GET("/user", settingsHandler.GetUserSettings)
			settings.POST("/user", settingsHandler.CreateUserSetting)
			settings.GET("/user/:key", settingsHandler.GetUserSetting)
			settings.PUT("/user/:key", settingsHandler.UpdateUserSetting)
			settings.DELETE("/user/:key", settingsHandler.DeleteUserSetting)

			// Security Policies
			settings.GET("/security/policies", middleware.RequireRole("admin"), settingsHandler.GetSecurityPolicies)
			settings.POST("/security/policies", middleware.RequireRole("admin"), settingsHandler.CreateSecurityPolicy)
			settings.GET("/security/policies/:id", middleware.RequireRole("admin"), settingsHandler.GetSecurityPolicy)
			settings.GET("/security/active-policy", settingsHandler.GetActiveSecurityPolicy)

			// Settings Metadata
			settings.GET("/categories", settingsHandler.GetSettingsCategories)
		}
	}
}
