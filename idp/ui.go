package idp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// The page is served by the IdP and talks only to the IdP. garm is reached
// through the proxy below rather than from the browser, and that is a
// deliberate choice rather than a shortcut: the alternative is CORS headers
// on the tool plane, and a governance product should not grow a mechanism for
// letting arbitrary web origins call it just so a dev tool can draw a list.
//
//go:embed ui.html
var uiHTML []byte

func (s *server) serveUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(uiHTML)
}

// serveVisibleTools mints for a persona and asks garm what that principal can
// see, which is the only part of this worth building a UI for.
//
// A token on its own tells you what was asserted. The catalogue tells you
// what it MEANS — and watching the tool list shrink when you route through a
// lower-privileged agent is the clearest demonstration of folding there is.
func (s *server) serveVisibleTools(w http.ResponseWriter, r *http.Request) {
	if s.personas == nil {
		http.Error(w, "no personas configured; use --personas", http.StatusNotFound)
		return
	}
	q := r.URL.Query()

	rec := httptestRecorder{header: http.Header{}}
	s.serveTokenForPersona(&rec, q.Get("user"), q.Get("as"), time.Now())
	if rec.status != 0 && rec.status != http.StatusOK {
		http.Error(w, rec.body.String(), rec.status)
		return
	}
	token := trimNewline(rec.body.String())

	body, status, err := postJSON(
		s.garmURL+"/garm.v1.ToolCatalogService/ListTools", token, `{}`)
	if err != nil {
		writeJSON(w, map[string]any{
			"error": fmt.Sprintf("could not reach garm at %s: %v", s.garmURL, err),
			"hint":  "is garmd running? `garmd serve --catalogue ...` in another terminal",
		})
		return
	}
	writeJSON(w, map[string]any{
		"token":  token,
		"status": status,
		"tools":  json.RawMessage(body),
	})
}

func postJSON(url, bearer, body string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return out, resp.StatusCode, err
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// httptestRecorder captures serveTokenForPersona's output so the proxy can
// reuse the minting path exactly rather than reimplementing it — the two
// would otherwise drift, and the entitlement check is the thing that would
// drift out.
type httptestRecorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (r *httptestRecorder) Header() http.Header { return r.header }
func (r *httptestRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}
func (r *httptestRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}
