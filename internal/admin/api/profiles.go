package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// ProfileHandler handles profile-related API requests.
type ProfileHandler struct {
	store  storage.ProfileStore
	logger zerolog.Logger
}

// NewProfileHandler creates a new profile handler.
func NewProfileHandler(store storage.ProfileStore, logger zerolog.Logger) *ProfileHandler {
	return &ProfileHandler{
		store:  store,
		logger: logger.With().Str("handler", "profile").Logger(),
	}
}

// List returns all profiles.
func (h *ProfileHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	profiles, err := h.store.List(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to list profiles")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve profiles")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"profiles": profiles,
		"count":    len(profiles),
	})
}

// Get returns a single profile by ID.
func (h *ProfileHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	id := vars["id"]

	profile, err := h.store.Get(ctx, id)
	if err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Profile not found")
			return
		}
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to get profile")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve profile")
		return
	}

	writeJSON(w, http.StatusOK, profile)
}

// Create creates a new profile.
func (h *ProfileHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var profile storage.Profile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate profile
	if profile.Name == "" {
		writeError(w, http.StatusBadRequest, "Profile name is required")
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

	if err := h.store.Upsert(ctx, profile); err != nil {
		h.logger.Error().Err(err).Msg("Failed to create profile")
		writeError(w, http.StatusInternalServerError, "Failed to create profile")
		return
	}

	h.logger.Info().Str("id", profile.ID).Str("name", profile.Name).Msg("Profile created")
	writeJSON(w, http.StatusCreated, profile)
}

// Update updates an existing profile.
func (h *ProfileHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	id := vars["id"]

	// Get existing profile
	existing, err := h.store.Get(ctx, id)
	if err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Profile not found")
			return
		}
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to get profile")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve profile")
		return
	}

	var updates storage.Profile
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Preserve ID and creation time
	updates.ID = existing.ID
	updates.CreatedAt = existing.CreatedAt
	updates.UpdatedAt = time.Now()

	// Validate updates
	if updates.Name == "" {
		writeError(w, http.StatusBadRequest, "Profile name is required")
		return
	}

	if err := h.store.Upsert(ctx, updates); err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to update profile")
		writeError(w, http.StatusInternalServerError, "Failed to update profile")
		return
	}

	h.logger.Info().Str("id", id).Str("name", updates.Name).Msg("Profile updated")
	writeJSON(w, http.StatusOK, updates)
}

// Delete deletes a profile.
func (h *ProfileHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	id := vars["id"]

	if err := h.store.Delete(ctx, id); err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Profile not found")
			return
		}
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to delete profile")
		writeError(w, http.StatusInternalServerError, "Failed to delete profile")
		return
	}

	h.logger.Info().Str("id", id).Msg("Profile deleted")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Profile deleted successfully",
	})
}
