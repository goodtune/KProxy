package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// ErrorResponse represents an API error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(data); err != nil {
		http.Error(w, `{"error":"Internal Server Error","message":"Failed to encode response"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(buf.Bytes())
}

// writeError writes an error response.
func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
		Code:    statusCode,
	})
}

// DeviceHandler handles device-related API requests.
type DeviceHandler struct {
	store  storage.DeviceStore
	logger zerolog.Logger
}

// NewDeviceHandler creates a new device handler.
func NewDeviceHandler(store storage.DeviceStore, logger zerolog.Logger) *DeviceHandler {
	return &DeviceHandler{
		store:  store,
		logger: logger.With().Str("handler", "device").Logger(),
	}
}

// List returns all devices.
func (h *DeviceHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	devices, err := h.store.List(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to list devices")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve devices")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"devices": devices,
		"count":   len(devices),
	})
}

// Get returns a single device by ID.
func (h *DeviceHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	id := vars["id"]

	device, err := h.store.Get(ctx, id)
	if err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Device not found")
			return
		}
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to get device")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve device")
		return
	}

	writeJSON(w, http.StatusOK, device)
}

// Create creates a new device.
func (h *DeviceHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var device storage.Device
	if err := json.NewDecoder(r.Body).Decode(&device); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate device
	if device.Name == "" {
		writeError(w, http.StatusBadRequest, "Device name is required")
		return
	}

	if len(device.Identifiers) == 0 {
		writeError(w, http.StatusBadRequest, "At least one identifier is required")
		return
	}

	// Generate ID if not provided
	if device.ID == "" {
		device.ID = generateID("dev")
	}

	// Set timestamps
	now := time.Now()
	device.CreatedAt = now
	device.UpdatedAt = now

	// Set default active state
	if !device.Active {
		device.Active = true
	}

	if err := h.store.Upsert(ctx, device); err != nil {
		h.logger.Error().Err(err).Msg("Failed to create device")
		writeError(w, http.StatusInternalServerError, "Failed to create device")
		return
	}

	h.logger.Info().Str("id", device.ID).Str("name", device.Name).Msg("Device created")
	writeJSON(w, http.StatusCreated, device)
}

// Update updates an existing device.
func (h *DeviceHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	id := vars["id"]

	// Get existing device
	existing, err := h.store.Get(ctx, id)
	if err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Device not found")
			return
		}
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to get device")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve device")
		return
	}

	var updates storage.Device
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
		writeError(w, http.StatusBadRequest, "Device name is required")
		return
	}

	if len(updates.Identifiers) == 0 {
		writeError(w, http.StatusBadRequest, "At least one identifier is required")
		return
	}

	if err := h.store.Upsert(ctx, updates); err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to update device")
		writeError(w, http.StatusInternalServerError, "Failed to update device")
		return
	}

	h.logger.Info().Str("id", id).Str("name", updates.Name).Msg("Device updated")
	writeJSON(w, http.StatusOK, updates)
}

// Delete deletes a device.
func (h *DeviceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	id := vars["id"]

	if err := h.store.Delete(ctx, id); err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Device not found")
			return
		}
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to delete device")
		writeError(w, http.StatusInternalServerError, "Failed to delete device")
		return
	}

	h.logger.Info().Str("id", id).Msg("Device deleted")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Device deleted successfully",
	})
}

// generateID generates a unique ID with a prefix.
func generateID(prefix string) string {
	return prefix + "-" + time.Now().Format("20060102150405")
}
