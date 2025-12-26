package admin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
)

// ProfileViews handles profile-related API requests.
type ProfileViews struct {
	store  storage.ProfileStore
	logger zerolog.Logger
}

// NewProfileViews creates a new profile views instance.
func NewProfileViews(store storage.ProfileStore, logger zerolog.Logger) *ProfileViews {
	return &ProfileViews{
		store:  store,
		logger: logger.With().Str("handler", "profile").Logger(),
	}
}

// List returns all profiles.
func (v *ProfileViews) List(ctx *gin.Context) {
	profiles, err := v.store.List(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to list profiles")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve profiles",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"profiles": profiles,
		"count":    len(profiles),
	})
}

// Get returns a single profile by ID.
func (v *ProfileViews) Get(ctx *gin.Context) {
	id := ctx.Param("id")

	profile, err := v.store.Get(ctx.Request.Context(), id)
	if err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Profile not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to get profile")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve profile",
		})
		return
	}

	ctx.JSON(http.StatusOK, profile)
}

// Create creates a new profile.
func (v *ProfileViews) Create(ctx *gin.Context) {
	var profile storage.Profile
	if err := ctx.ShouldBindJSON(&profile); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	// Validate profile
	if profile.Name == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Profile name is required",
		})
		return
	}

	// Generate ID if not provided
	if profile.ID == "" {
		profile.ID = generateID("profile")
	}

	// Set timestamps
	now := time.Now()
	profile.CreatedAt = now
	profile.UpdatedAt = now

	if err := v.store.Upsert(ctx.Request.Context(), profile); err != nil {
		v.logger.Error().Err(err).Msg("Failed to create profile")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to create profile",
		})
		return
	}

	v.logger.Info().Str("id", profile.ID).Str("name", profile.Name).Msg("Profile created")
	ctx.JSON(http.StatusCreated, profile)
}

// Update updates an existing profile.
func (v *ProfileViews) Update(ctx *gin.Context) {
	id := ctx.Param("id")

	// Get existing profile
	existing, err := v.store.Get(ctx.Request.Context(), id)
	if err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Profile not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to get profile")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve profile",
		})
		return
	}

	var updates storage.Profile
	if err := ctx.ShouldBindJSON(&updates); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	// Preserve ID and creation time
	updates.ID = existing.ID
	updates.CreatedAt = existing.CreatedAt
	updates.UpdatedAt = time.Now()

	// Validate updates
	if updates.Name == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Profile name is required",
		})
		return
	}

	if err := v.store.Upsert(ctx.Request.Context(), updates); err != nil {
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to update profile")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to update profile",
		})
		return
	}

	v.logger.Info().Str("id", id).Str("name", updates.Name).Msg("Profile updated")
	ctx.JSON(http.StatusOK, updates)
}

// Delete deletes a profile.
func (v *ProfileViews) Delete(ctx *gin.Context) {
	id := ctx.Param("id")

	if err := v.store.Delete(ctx.Request.Context(), id); err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Profile not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to delete profile")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to delete profile",
		})
		return
	}

	v.logger.Info().Str("id", id).Msg("Profile deleted")
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Profile deleted successfully",
	})
}
