package admin

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/goodtune/kproxy/internal/usage"
	"github.com/goodtune/kproxy/web"
	"github.com/rs/zerolog"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/goodtune/kproxy/docs" // Import generated docs
)

// AdminDeps holds dependencies needed for admin routes.
type AdminDeps struct {
	Store storage.Store
	Auth          *AuthService
	PolicyEngine  *policy.Engine
	UsageTracker  *usage.Tracker
	Logger        zerolog.Logger
	AllowedOrigins []string
}

// SetupGorfRoutes registers all admin routes with the Gin engine.
func SetupGorfRoutes(r *gin.Engine, deps *AdminDeps) {
	// Create rate limiter (100 requests per minute)
	rateLimiter := NewRateLimiter(100, time.Minute)

	// Global middleware
	r.Use(LoggingMiddlewareGin(deps.Logger))
	r.Use(RateLimitMiddlewareGin(rateLimiter))

	if len(deps.AllowedOrigins) > 0 {
		r.Use(CORSMiddlewareGin(deps.AllowedOrigins))
	}

	// Initialize view handlers
	authViews := NewAuthViews(deps.Auth, deps.Logger)
	deviceViews := NewDeviceViews(deps.Store.Devices(), deps.Logger)
	profileViews := NewProfileViews(deps.Store.Profiles(), deps.Logger)
	rulesViews := NewRulesViews(deps.Store.Rules(), deps.Store.TimeRules(), deps.Store.UsageLimits(), deps.Store.BypassRules(), deps.PolicyEngine, deps.Logger)
	logsViews := NewLogsViews(deps.Store.Logs(), deps.Logger)
	sessionsViews := NewSessionsViews(deps.Store.Usage(), deps.Logger)
	statsViews := NewStatsViews(deps.Store.Devices(), deps.Store.Profiles(), deps.Store.Rules(), deps.Store.Logs(), deps.Store.Usage(), deps.Logger)
	systemViews := NewSystemViews(deps.PolicyEngine, deps.Logger)

	// Health check (public)
	r.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"status": "ok"})
	})

	// Swagger API documentation (public) - must be registered before other /api routes
	r.GET("/api/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.GET("/api/", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Authentication endpoints (public)
	auth := r.Group("/api/auth")
	{
		auth.POST("/login", authViews.Login)
		auth.POST("/logout", authViews.Logout)
	}

	// Protected API routes
	api := r.Group("/api")
	api.Use(AuthMiddlewareGin(deps.Auth))
	{
		// Auth endpoints (authenticated)
		api.GET("/auth/me", authViews.Me)
		api.POST("/auth/change-password", authViews.ChangePassword)

		// Device management
		devices := api.Group("/devices")
		{
			devices.GET("", deviceViews.List)
			devices.POST("", deviceViews.Create)
			devices.GET("/:id", deviceViews.Get)
			devices.PUT("/:id", deviceViews.Update)
			devices.DELETE("/:id", deviceViews.Delete)
		}

		// Profile management
		profiles := api.Group("/profiles")
		{
			profiles.GET("", profileViews.List)
			profiles.POST("", profileViews.Create)
			profiles.GET("/:id", profileViews.Get)
			profiles.PUT("/:id", profileViews.Update)
			profiles.DELETE("/:id", profileViews.Delete)
		}

		// Rules management (global - list all rules)
		rules := api.Group("/rules")
		{
			rules.GET("", rulesViews.ListAllRules)
		}

		// Rules management (nested under profiles)
		profileRules := api.Group("/profiles/:id")
		{
			// Regular rules
			profileRules.GET("/rules", rulesViews.ListRules)
			profileRules.POST("/rules", rulesViews.CreateRule)
			profileRules.GET("/rules/:ruleID", rulesViews.GetRule)
			profileRules.PUT("/rules/:ruleID", rulesViews.UpdateRule)
			profileRules.DELETE("/rules/:ruleID", rulesViews.DeleteRule)

			// Time rules
			profileRules.GET("/time-rules", rulesViews.ListTimeRules)
			profileRules.POST("/time-rules", rulesViews.CreateTimeRule)
			profileRules.DELETE("/time-rules/:ruleID", rulesViews.DeleteTimeRule)

			// Usage limits
			profileRules.GET("/usage-limits", rulesViews.ListUsageLimits)
			profileRules.POST("/usage-limits", rulesViews.CreateUsageLimit)
			profileRules.DELETE("/usage-limits/:limitID", rulesViews.DeleteUsageLimit)
		}

		// Bypass rules (global)
		bypassRules := api.Group("/bypass-rules")
		{
			bypassRules.GET("", rulesViews.ListBypassRules)
			bypassRules.POST("", rulesViews.CreateBypassRule)
			bypassRules.DELETE("/:id", rulesViews.DeleteBypassRule)
		}

		// Logs management
		logs := api.Group("/logs")
		{
			logs.GET("/requests", logsViews.QueryRequestLogs)
			logs.GET("/dns", logsViews.QueryDNSLogs)
			logs.DELETE("/requests/:days", logsViews.DeleteOldRequestLogs)
			logs.DELETE("/dns/:days", logsViews.DeleteOldDNSLogs)
		}

		// Sessions and usage tracking
		sessions := api.Group("/sessions")
		{
			sessions.GET("", sessionsViews.ListActiveSessions)
			sessions.GET("/:id", sessionsViews.GetSession)
			sessions.DELETE("/:id", sessionsViews.TerminateSession)
		}

		usage := api.Group("/usage")
		{
			usage.GET("/today", sessionsViews.GetTodayUsage)
			usage.GET("/:date", sessionsViews.GetDailyUsage)
		}

		// Statistics
		stats := api.Group("/stats")
		{
			stats.GET("/dashboard", statsViews.GetDashboardStats)
			stats.GET("/devices", statsViews.GetDeviceStats)
			stats.GET("/top-domains", statsViews.GetTopDomains)
			stats.GET("/blocked", statsViews.GetBlockedStats)
		}

		// System control
		system := api.Group("/system")
		{
			system.POST("/reload", systemViews.ReloadPolicy)
			system.GET("/health", systemViews.GetHealth)
			system.GET("/info", systemViews.GetSystemInfo)
			system.GET("/config", systemViews.GetConfig)
		}
	}

	// Setup UI routes (must be last to handle SPA routing)
	web.SetupUIRoutes(r)
}
