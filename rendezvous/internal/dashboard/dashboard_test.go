package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knockknock/rendezvous/internal/registry"
)

func TestHandler(t *testing.T) {
	h := Handler(func() registry.Snapshot {
		return registry.Snapshot{Clients: 2, Lobbies: []registry.LobbySnapshot{{ID: "K7M2QX"}}}
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/lobbies", nil))
	var snap registry.Snapshot
	if err := json.NewDecoder(rec.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	if snap.Clients != 2 || len(snap.Lobbies) != 1 || snap.Lobbies[0].ID != "K7M2QX" {
		t.Errorf("got %+v", snap)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rec.Body.String(), "<title>knockknock") {
		t.Error("index page not served")
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown path: status %d", rec.Code)
	}
}
