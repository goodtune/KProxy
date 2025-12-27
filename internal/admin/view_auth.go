package admin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// AuthViews handles authentication-related endpoints.
type AuthViews struct {
	auth   *AuthService
	logger zerolog.Logger
}

// NewAuthViews creates a new AuthViews instance.
func NewAuthViews(auth *AuthService, logger zerolog.Logger) *AuthViews {
	return &AuthViews{
		auth:   auth,
		logger: logger,
	}
}

// Login handles user login requests.
func (v *AuthViews) Login(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	// Validate input
	if req.Username == "" || req.Password == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Username and password are required",
		})
		return
	}

	// Attempt login
	session, token, err := v.auth.Login(ctx.Request.Context(), req.Username, req.Password)
	if err != nil {
		if err == ErrInvalidCredentials {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid username or password",
			})
			return
		}
		v.logger.Error().Err(err).Msg("Login error")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Login failed",
		})
		return
	}

	// Set cookies (admin interface uses HTTPS)
	ctx.SetCookie(
		"admin_token",
		token,
		int(session.ExpiresAt.Sub(time.Now()).Seconds()),
		"/",
		"",
		true,  // Secure
		true,  // HttpOnly
	)

	ctx.SetCookie(
		"admin_session",
		session.ID,
		int(session.ExpiresAt.Sub(time.Now()).Seconds()),
		"/",
		"",
		true,  // Secure
		true,  // HttpOnly
	)

	// Return response
	resp := LoginResponse{
		Token:     token,
		ExpiresAt: session.ExpiresAt,
		User: UserInfo{
			ID:       session.UserID,
			Username: session.Username,
		},
	}

	ctx.JSON(http.StatusOK, resp)

	v.logger.Info().
		Str("username", req.Username).
		Str("session_id", session.ID).
		Msg("User logged in")
}

// Logout handles user logout requests.
func (v *AuthViews) Logout(ctx *gin.Context) {
	// Get session ID from context or cookie
	sessionID, exists := ctx.Get("session_id")
	if !exists {
		sessionID, _ = ctx.Cookie("admin_session")
	}

	// Logout session
	if sessionIDStr, ok := sessionID.(string); ok && sessionIDStr != "" {
		if err := v.auth.Logout(sessionIDStr); err != nil {
			v.logger.Error().Err(err).Str("session_id", sessionIDStr).Msg("Logout error")
		}
	}

	// Clear cookies
	ctx.SetCookie("admin_token", "", -1, "/", "", false, true)
	ctx.SetCookie("admin_session", "", -1, "/", "", false, true)

	// Return success
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})

	if sessionIDStr, ok := sessionID.(string); ok {
		v.logger.Info().Str("session_id", sessionIDStr).Msg("User logged out")
	}
}

// Me returns the current user information.
func (v *AuthViews) Me(ctx *gin.Context) {
	userID, _ := ctx.Get("user_id")
	username, _ := ctx.Get("username")

	user := UserInfo{
		ID:       userID.(string),
		Username: username.(string),
	}

	ctx.JSON(http.StatusOK, user)
}

// ChangePassword handles password change requests.
func (v *AuthViews) ChangePassword(ctx *gin.Context) {
	username, exists := ctx.Get("username")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}

	var req ChangePasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	// Validate input
	if req.OldPassword == "" || req.NewPassword == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Old and new passwords are required",
		})
		return
	}

	if len(req.NewPassword) < 8 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "New password must be at least 8 characters",
		})
		return
	}

	// Change password
	usernameStr := username.(string)
	if err := v.auth.ChangePassword(ctx.Request.Context(), usernameStr, req.OldPassword, req.NewPassword); err != nil {
		if err == ErrInvalidCredentials {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid current password",
			})
			return
		}
		v.logger.Error().Err(err).Str("username", usernameStr).Msg("Password change error")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to change password",
		})
		return
	}

	// Return success
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})

	v.logger.Info().Str("username", usernameStr).Msg("User changed password")
}
