package admin

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleLogin handles user login requests.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate input
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	// Attempt login
	session, token, err := s.auth.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		if err == ErrInvalidCredentials {
			writeError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}
		s.logger.Error().Err(err).Msg("Login error")
		writeError(w, http.StatusInternalServerError, "Login failed")
		return
	}

	// Set cookies (admin interface is always HTTPS)
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Admin interface uses HTTPS
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Admin interface uses HTTPS
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt,
	})

	// Return response
	resp := LoginResponse{
		Token:     token,
		ExpiresAt: session.ExpiresAt,
		User: UserInfo{
			ID:       session.UserID,
			Username: session.Username,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)

	s.logger.Info().
		Str("username", req.Username).
		Str("session_id", session.ID).
		Msg("User logged in")
}

// handleLogout handles user logout requests.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Get session ID from context or cookie
	sessionID, _ := GetSessionFromContext(r.Context())
	if sessionID == "" {
		cookie, err := r.Cookie("admin_session")
		if err == nil {
			sessionID = cookie.Value
		}
	}

	// Logout session
	if sessionID != "" {
		if err := s.auth.Logout(sessionID); err != nil {
			s.logger.Error().Err(err).Str("session_id", sessionID).Msg("Logout error")
		}
	}

	// Clear cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})

	// Return success
	resp := SuccessResponse{
		Message: "Logged out successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)

	s.logger.Info().Str("session_id", sessionID).Msg("User logged out")
}

// handleMe returns the current user information.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	userID, _ := GetUserIDFromContext(r.Context())
	username, _ := GetUsernameFromContext(r.Context())

	user := UserInfo{
		ID:       userID,
		Username: username,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// handleChangePassword handles password change requests.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	username, ok := GetUsernameFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate input
	if req.OldPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "Old and new passwords are required")
		return
	}

	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "New password must be at least 8 characters")
		return
	}

	// Change password
	if err := s.auth.ChangePassword(r.Context(), username, req.OldPassword, req.NewPassword); err != nil {
		if err == ErrInvalidCredentials {
			writeError(w, http.StatusUnauthorized, "Invalid current password")
			return
		}
		s.logger.Error().Err(err).Str("username", username).Msg("Password change error")
		writeError(w, http.StatusInternalServerError, "Failed to change password")
		return
	}

	// Return success
	resp := SuccessResponse{
		Message: "Password changed successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)

	s.logger.Info().Str("username", username).Msg("User changed password")
}
