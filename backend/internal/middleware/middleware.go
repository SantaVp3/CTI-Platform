package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"cti-platform/internal/config"
	"cti-platform/internal/services"

	"github.com/gin-gonic/gin"
)

// Simple rate limiter implementation
type rateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()

	// Clean up expired request records
	if requests, exists := rl.requests[key]; exists {
		validRequests := make([]time.Time, 0)
		for _, reqTime := range requests {
			if now.Sub(reqTime) < rl.window {
				validRequests = append(validRequests, reqTime)
			}
		}
		rl.requests[key] = validRequests
	}

	// Check if limit is exceeded
	if len(rl.requests[key]) >= rl.limit {
		return false
	}

	// Add current request
	rl.requests[key] = append(rl.requests[key], now)
	return true
}

// CORS middleware
func CORS(cfg *config.Config) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range cfg.Security.CORSAllowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}
		
		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
}

// Rate limiting middleware
func RateLimit(cfg *config.Config) gin.HandlerFunc {
	limiter := newRateLimiter(cfg.Security.RateLimitRequestsPerMin, time.Minute)

	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := c.ClientIP()
		if !limiter.allow(clientIP) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			c.Abort()
			return
		}
		c.Next()
	})
}

// Security headers middleware
func Security() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	})
}

// Authentication middleware
func Auth(authService *services.AuthService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "需要授权头",
			})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		token := parts[1]
		claims, err := authService.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		// Set user information in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	})
}

// Role-based authorization middleware
func RequireRole(roles ...string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		userRole, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "User role not found",
			})
			c.Abort()
			return
		}

		roleStr, ok := userRole.(string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Invalid user role",
			})
			c.Abort()
			return
		}

		// Check if user has required role
		for _, role := range roles {
			if roleStr == role {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error": "权限不足",
		})
		c.Abort()
	})
}

// Audit logging middleware
func AuditLog(auditService *services.AuditService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Store request start time
		start := time.Now()
		
		// Process request
		c.Next()
		
		// Log the request after processing
		go func() {
			userID, _ := c.Get("user_id")
			
			auditService.LogAction(services.AuditLogEntry{
				UserID:       getUserIDFromContext(userID),
				Action:       c.Request.Method + " " + c.Request.URL.Path,
				ResourceType: "api_request",
				IPAddress:    c.ClientIP(),
				UserAgent:    c.Request.UserAgent(),
				Duration:     time.Since(start),
				StatusCode:   c.Writer.Status(),
			})
		}()
	})
}

func getUserIDFromContext(userID interface{}) *uint {
	if userID == nil {
		return nil
	}
	
	if id, ok := userID.(uint); ok {
		return &id
	}
	
	return nil
}
