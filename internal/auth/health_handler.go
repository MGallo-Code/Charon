// health_handler.go -- Health check handler for GET /health.
package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/MGallo-Code/charon/internal/store"
)

// CheckHealth handles GET /health — pings Postgres and Redis, returns per-dependency status.
// Returns 200 if both are healthy, 503 if either is down.
func (h *AuthHandler) CheckHealth(w http.ResponseWriter, r *http.Request) {
	redisStatus := "ok"
	postgresStatus := "ok"

	if err := h.RS.CheckHealth(r.Context()); err != nil {
		if errors.Is(err, store.ErrCacheDisabled) {
			redisStatus = "disabled"
		} else {
			logError(r, "redis health check failed", "error", err)
			redisStatus = "error"
		}
	}
	if err := h.PS.CheckHealth(r.Context()); err != nil {
		logError(r, "postgres health check failed", "error", err)
		postgresStatus = "error"
	}

	w.Header().Set("Content-Type", "application/json")
	if redisStatus == "error" || postgresStatus == "error" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(struct {
		Postgres string `json:"postgres"`
		Redis    string `json:"redis"`
	}{postgresStatus, redisStatus})
}
