package executor

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
)

// Handler is the execution-tool API the orchestrator calls. It is on the
// platform network only; sandboxes cannot route to it.
func (m *Manager) Handler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		var req CreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpErr(w, http.StatusBadRequest, err)
			return
		}
		s, err := m.Create(r.Context(), req)
		if err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, ErrNotGranted) {
				code = http.StatusForbidden
			}
			httpErr(w, code, err)
			return
		}
		writeJSON(w, http.StatusCreated, s.snapshot())
	})
	mux.HandleFunc("POST /v1/sessions/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		var req ExecRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpErr(w, http.StatusBadRequest, err)
			return
		}
		res, err := m.Exec(r.Context(), r.PathValue("id"), req)
		if err != nil {
			httpErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := m.Delete(r.Context(), r.PathValue("id"), "requested"); err != nil {
			httpErr(w, http.StatusNotFound, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, m.List())
	})
	mux.HandleFunc("GET /v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, m.Metrics())
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Write([]byte("ok"))
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
