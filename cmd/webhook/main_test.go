package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpoints(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "healthz", handler: healthz},
		{name: "readyz", handler: readyz},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/"+tt.name, nil)
			rec := httptest.NewRecorder()

			tt.handler(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
			}
			if rec.Body.String() != "ok" {
				t.Fatalf("got body %q, want %q", rec.Body.String(), "ok")
			}
			if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
				t.Fatalf("got content type %q, want %q", got, "text/plain; charset=utf-8")
			}
		})
	}
}
