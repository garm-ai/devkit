// Package idp serves a JWKS and mints tokens, so a local garmd can verify
// real signatures with no identity provider in the picture.
//
// Why it may not import the verifier.
//
// This mints tokens; garmd's authn package decides what a token means. Those
// two must not live in one dependency graph, because the moment they do,
// something in a request path can reach a minter. The repository boundary is
// the guard — see cmd/garmdev/main.go — and the consequence is here: the
// token body below is written as plain JSON, and this file knows nothing
// about the types that will read it.
//
// That leaves one hazard, drift: the body and the verifier disagreeing
// silently until every dev token stops verifying for a reason nobody can
// see. See KNOWN-GAPS.md — it is a named gap, not a solved problem.
package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/spf13/cobra"
)

// devIssuer is the `iss` every token from this server carries. It is not a
// URL that resolves, and that is deliberate: nothing should be able to
// discover this issuer, only be configured to trust it.
const devIssuer = "https://garmdev.invalid/idp"

type Config struct {
	Audience string
	TTL      time.Duration

	// Personas, when configured, add /personas and the ?user= / ?as= form
	// of /token. Without them the raw ?clearance=&compartments= form is
	// still there, which is what an ad-hoc test wants.
	Personas *personas

	// GarmURL is the tool plane the UI asks what a principal can see.
	GarmURL string
}

type server struct {
	key      *ecdsa.PrivateKey
	kid      string
	jwks     []byte
	audience string
	ttl      time.Duration
	personas *personas
	garmURL  string
}

func New(cfg Config) (http.Handler, error) {
	if cfg.Audience == "" {
		cfg.Audience = "garm"
	}
	if cfg.TTL == 0 {
		cfg.TTL = time.Hour
	}

	// An ephemeral key per run. Tokens do not survive a restart, which is
	// the right default for a thing whose tokens should never be worth
	// keeping.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating the dev signing key: %w", err)
	}
	kid := fmt.Sprintf("garmdev-%d", time.Now().UnixNano())

	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key.Public(),
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}}}
	jwks, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("encoding the key set: %w", err)
	}

	s := &server{
		key: key, kid: kid, jwks: jwks,
		audience: cfg.Audience, ttl: cfg.TTL, personas: cfg.Personas,
		garmURL: orDefault(cfg.GarmURL, "http://127.0.0.1:7440"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.serveJWKS)
	mux.HandleFunc("/token", s.serveToken)
	mux.HandleFunc("/personas", s.servePersonas)
	mux.HandleFunc("/tools", s.serveVisibleTools)
	mux.HandleFunc("/", s.serveUI)
	return mux, nil
}

func (s *server) serveJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.jwks)
}

// serveToken mints a token from query parameters.
//
// Query parameters rather than a JSON body so the whole thing is one curl,
// and so the command that produces a token reads like the identity it is
// asking for.
// servePersonas lists what is configured. Read-only, and there is no write
// counterpart on purpose — see personas.go.
func (s *server) servePersonas(w http.ResponseWriter, r *http.Request) {
	if s.personas == nil {
		http.Error(w, "no personas configured; use --personas", http.StatusNotFound)
		return
	}
	out := map[string]any{
		"roles":  s.personas.Roles,
		"users":  s.personas.Users,
		"agents": s.personas.Agents,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *server) serveToken(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := time.Now()

	if user := q.Get("user"); user != "" {
		s.serveTokenForPersona(w, user, q.Get("as"), now)
		return
	}

	body := map[string]any{
		"iss":  devIssuer,
		"sub":  orDefault(q.Get("sub"), "dev-user"),
		"aud":  s.audience,
		"jti":  fmt.Sprintf("garmdev-%d", now.UnixNano()),
		"iat":  now.Unix(),
		"exp":  now.Add(s.ttl).Unix(),
		"garm": garmClaim(q.Get("clearance"), q.Get("compartments"), q.Get("verbs"), q.Get("tool_sets")),
	}
	if tenant := q.Get("tenant"); tenant != "" {
		body["tenant"] = tenant
	}
	// The `act` chain: who is ACTING for the subject. Folding takes the
	// minimum of every identity in it, so adding a hop can only narrow
	// authority — which is the property worth being able to demonstrate.
	if actor := q.Get("act"); actor != "" {
		body["act"] = map[string]any{
			"sub": actor,
			"garm": garmClaim(
				orDefault(q.Get("act_clearance"), q.Get("clearance")),
				orDefault(q.Get("act_compartments"), q.Get("compartments")),
				orDefault(q.Get("act_verbs"), q.Get("verbs")),
				"",
			),
		}
	}

	token, err := s.sign(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, token)
}

// serveTokenForPersona mints for a configured user, optionally delegated.
func (s *server) serveTokenForPersona(w http.ResponseWriter, user, actor string, now time.Time) {
	if s.personas == nil {
		http.Error(w, "no personas configured; use --personas", http.StatusNotFound)
		return
	}
	u, ok := s.personas.Users[user]
	if !ok {
		http.Error(w, fmt.Sprintf("no user %q in the personas file", user), http.StatusNotFound)
		return
	}

	ua := s.personas.expand(u)
	body := map[string]any{
		"iss":  devIssuer,
		"sub":  orDefault(u.Subject, "user:"+user),
		"aud":  s.audience,
		"jti":  fmt.Sprintf("garmdev-%d", now.UnixNano()),
		"iat":  now.Unix(),
		"exp":  now.Add(s.ttl).Unix(),
		"garm": claimFromAuthority(ua, "USER"),
	}

	if actor != "" {
		a, ok := s.personas.Agents[actor]
		if !ok {
			http.Error(w, fmt.Sprintf("no agent %q in the personas file", actor), http.StatusNotFound)
			return
		}
		// The entitlement check. garm cannot make it: it folds a chain it is
		// given and can only narrow it, but it has no way to know whether
		// the delegation was permitted. The IdP asserts that by signing.
		if !s.personas.mayActFor(actor, user) {
			http.Error(w, fmt.Sprintf(
				"agent %q is not entitled to act for %q; add it to may_act_for if it should be",
				actor, user), http.StatusForbidden)
			return
		}
		aa := s.personas.expand(a)
		body["act"] = map[string]any{
			"sub":  orDefault(a.Subject, "agent:"+actor),
			"garm": claimFromAuthority(aa, "AGENT"),
		}
	}

	token, err := s.sign(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, token)
}

// claimFromAuthority renders the `garm` claim a role expansion produces.
//
// Note what is NOT here: the role names. garm never sees a role — it receives
// the clearance, compartments and verbs a role expands to. A role reaching
// the policy chain would be a second vocabulary for answering the same
// question.
func claimFromAuthority(a authority, kind string) map[string]any {
	c := map[string]any{
		"clearance": a.Clearance,
		"kind":      kind,
	}
	if len(a.Compartments) > 0 {
		c["compartments"] = a.Compartments
	}
	if len(a.Verbs) > 0 {
		c["verbs"] = a.Verbs
	}
	if len(a.ToolSets) > 0 {
		c["tool_sets"] = a.ToolSets
	}
	return c
}

func (s *server) sign(body map[string]any) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: s.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.kid),
	)
	if err != nil {
		return "", fmt.Errorf("building the signer: %w", err)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encoding the token body: %w", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return obj.CompactSerialize()
}

func garmClaim(clearance, compartments, verbs, sets string) map[string]any {
	c := map[string]any{
		"clearance": canonicalClearance(orDefault(clearance, "CLEARANCE_INTERNAL")),
	}
	if v := splitList(compartments); len(v) > 0 {
		c["compartments"] = v
	}
	c["verbs"] = splitListOr(verbs, []string{"VERB_READ"})
	if v := splitList(sets); len(v) > 0 {
		c["tool_sets"] = v
	}
	return c
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitListOr(s string, fallback []string) []string {
	if v := splitList(s); len(v) > 0 {
		return v
	}
	return fallback
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// checkLoopback refuses any address reachable from another machine.
//
// A token minter on a shared interface is a way for anyone who can reach it
// to mint any identity — a higher clearance, another tenant, a delegation
// chain that never happened. There is no authentication on /token and there
// should not be: the whole point is that it hands out identities freely,
// which is only safe when nothing else can ask.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not host:port: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("%q binds every interface; the dev IdP mints any identity "+
			"asked of it and must not be reachable off this machine — use 127.0.0.1", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%q is not an IP address; use 127.0.0.1", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%q is not a loopback address; the dev IdP mints any identity "+
			"asked of it and must not be reachable off this machine", host)
	}
	return nil
}

func Command() *cobra.Command {
	var addr string
	var audience string
	var ttl time.Duration
	var personasPath string
	var garmURL string

	cmd := &cobra.Command{
		Use:   "idp",
		Short: "Run a local identity provider for development",
		Long: "Serves a JWKS and mints tokens on demand, so a local garm can verify\n" +
			"real signatures without an identity provider.\n\n" +
			"It mints ANY identity it is asked for, with no authentication, which is\n" +
			"the point and also why it refuses to bind anything but loopback. Never\n" +
			"point a deployment at it: garm would then trust an issuer that hands out\n" +
			"clearances to whoever asks.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkLoopback(addr); err != nil {
				return err
			}
			cfg := Config{Audience: audience, TTL: ttl, GarmURL: garmURL}
			if personasPath != "" {
				p, err := loadPersonas(personasPath)
				if err != nil {
					return err
				}
				cfg.Personas = p
			}
			h, err := New(cfg)
			if err != nil {
				return err
			}
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listen %s: %w", addr, err)
			}
			base := "http://" + ln.Addr().String()
			fmt.Fprintf(os.Stderr, `garmdev idp — DEVELOPMENT ONLY, mints any identity asked of it

  jwks_url  %s/.well-known/jwks.json
  issuer    %s
  audience  %s

  UI:       %s
  a token:  curl -s '%s/token?user=alice'
  delegated: curl -s '%s/token?user=bob&as=triage-bot'

`, base, devIssuer, audience, base, base, base)
			return http.Serve(ln, h)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:7450", "loopback address to serve on")
	cmd.Flags().StringVar(&audience, "audience", "garm", "the aud minted tokens carry")
	cmd.Flags().DurationVar(&ttl, "ttl", time.Hour, "how long minted tokens are valid")
	cmd.Flags().StringVar(&garmURL, "garm-url", "http://127.0.0.1:7440",
		"the tool plane the UI asks what each principal can see")
	cmd.Flags().StringVar(&personasPath, "personas", "",
		"a personas file defining roles, users, agents and who may act for whom")
	return cmd
}
