// Package dashboard serves a read-only web view of the rendezvous server's
// lobbies and the connection stats reported by their hosts.
package dashboard

import (
	_ "embed"
	"encoding/json"
	"net/http"

	"knockknock/rendezvous/internal/registry"
)

//go:embed index.html
var index []byte

// Handler serves the dashboard page at / and its data at /api/lobbies.
func Handler(snapshot func() registry.Snapshot) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(index)
	})
	mux.HandleFunc("GET /api/lobbies", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(snapshot())
	})
	return mux
}
