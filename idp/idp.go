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
// The `garmdev idp` subcommand is the way you run this. Serve is exported —
// and this package therefore sits outside internal/ — so that garm-ai/stack's
// garmstack can run it as one component of a whole stack in a single process
// for local development. That is the only kind of process it belongs in: it
// mints any identity asked of it, which is why it refuses to bind anything
// but loopback.
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
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// DevIssuer is the `iss` every token from this server carries unless
// Config.Issuer says otherwise. It is not a URL that resolves, and that is
// deliberate: nothing should be able to discover this issuer, only be
// configured to trust it. It is exported because every process that must
// TRUST these tokens — garmd, the STS, and garmstack configuring both — has
// to name it.
const DevIssuer = "https://garmdev.invalid/idp"

type Config struct {
	// Addr is the loopback address to serve on. Serve refuses anything
	// else: see checkLoopback.
	Addr string

	Audience string
	TTL      time.Duration

	// Issuer is the `iss` minted tokens carry. Empty means DevIssuer,
	// which is what the binary always uses — there is no --issuer flag,
	// because a dev minter that can claim to be somebody else's issuer is
	// a worse thing to leave lying around than one that cannot.
	Issuer string

	// PersonasPath is the personas file Serve loads, if any. New takes the
	// loaded form below instead; a caller outside this package gives the
	// path and lets Serve read it.
	PersonasPath string

	// Personas, when configured, add /personas and the ?user= / ?as= form
	// of /token. Without them the raw ?clearance=&compartments= form is
	// still there, which is what an ad-hoc test wants.
	Personas *personas

	// GarmURL is the tool plane the UI asks what a principal can see.
	GarmURL string

	// OnListen is told the address the server actually bound, once it has.
	// A caller that passed :0 — or a command that prints a banner naming
	// the address — has no other way to learn it.
	OnListen func(addr string)

	// Tenant overrides the personas file's tenant for every identity this
	// server mints. Everything downstream refuses a token with no tenant —
	// the STS will not exchange one, because confinement depends on the value
	// flowing from a verified token — so this is not decoration.
	Tenant string
}

type server struct {
	key      *ecdsa.PrivateKey
	kid      string
	jwks     []byte
	audience string
	issuer   string
	ttl      time.Duration
	tenant   string
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
	if cfg.Issuer == "" {
		cfg.Issuer = DevIssuer
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
		audience: cfg.Audience, issuer: cfg.Issuer, ttl: cfg.TTL, tenant: cfg.Tenant,
		personas: cfg.Personas,
		garmURL:  orDefault(cfg.GarmURL, "http://127.0.0.1:7440"),
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

	// The principal kind. Absent means absent: a token nobody asked a kind
	// for must carry none, because that is how every caller that predates
	// this parameter is already read, and stamping a default would change
	// which principal each of those tokens resolves to.
	//
	// A value that IS given is checked here rather than passed through — see
	// canonicalKind for why this is the only place that can.
	var kind string
	if raw := q.Get("kind"); raw != "" {
		k, err := canonicalKind(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		kind = k
	}

	tenant := q.Get("tenant")
	if kind == "SERVICE" {
		// A service calls on its OWN behalf; that is what distinguishes it
		// from an agent. A chain baked into the identity would make every
		// call that service ever makes look delegated, and a runner's chain
		// is added per call by the platform anyway.
		if actor := q.Get("act"); actor != "" {
			http.Error(w, fmt.Sprintf(
				"a service token may not carry an act chain (act=%q); a service calls "+
					"on its own behalf, and the delegation chain belongs on the call "+
					"rather than in the identity", actor), http.StatusBadRequest)
			return
		}
		if tenant == "" {
			// Falling back only for a service, not for every ad-hoc token:
			// a --tenant that suddenly started stamping tokens that have
			// never carried one would change every existing caller.
			tenant = s.tenantFor("")
		}
		if tenant == "" {
			// No tenant means no tenant claim, which the STS refuses to
			// exchange — confinement depends on the value flowing from a
			// verified token. Refused here, where the message can say that,
			// rather than later as an access_denied that mentions no tenant.
			http.Error(w, "a service token must name a tenant: pass ?tenant=, or start "+
				"the IdP with --tenant; everything downstream refuses a token with none",
				http.StatusBadRequest)
			return
		}
	}

	body := map[string]any{
		"iss":  s.issuer,
		"sub":  orDefault(q.Get("sub"), "dev-user"),
		"aud":  s.audience,
		"jti":  fmt.Sprintf("garmdev-%d", now.UnixNano()),
		"iat":  now.Unix(),
		"exp":  now.Add(s.ttl).Unix(),
		"garm": garmClaim(kind, q.Get("clearance"), q.Get("compartments"), q.Get("verbs"), q.Get("tool_sets")),
	}
	if tenant != "" {
		body["tenant"] = tenant
	}
	// The `act` chain: who is ACTING for the subject. Folding takes the
	// minimum of every identity in it, so adding a hop can only narrow
	// authority — which is the property worth being able to demonstrate.
	if actor := q.Get("act"); actor != "" {
		body["act"] = map[string]any{
			"sub": actor,
			"garm": garmClaim(
				// No kind on the actor: ?kind= names the kind of the
				// SUBJECT, and inventing one for the actor would assert
				// something nobody asked for.
				"",
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
		"iss":  s.issuer,
		"sub":  orDefault(u.Subject, "user:"+user),
		"aud":  s.audience,
		"jti":  fmt.Sprintf("garmdev-%d", now.UnixNano()),
		"iat":  now.Unix(),
		"exp":  now.Add(s.ttl).Unix(),
		"garm": claimFromAuthority(ua, "USER"),
	}
	// The SUBJECT's tenant, and only the subject's. A delegated token's
	// authority is intersected across the chain, but whose data is in scope
	// is not a matter of intersection: an agent acting for jdoe is working on
	// jdoe's tenant's data, and there is no second tenant to reconcile.
	if tenant := s.tenantFor(u.Tenant); tenant != "" {
		body["tenant"] = tenant
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

// tenantFor resolves the tenant this identity's token carries: its own, then
// --tenant, then the personas file's. Most specific wins, which is the order
// every other override in this package uses.
//
// It takes the identity's own value rather than a persona so that a service —
// which is not in the personas file — resolves a tenant the same way, instead
// of a second rule nobody would think to keep in step.
func (s *server) tenantFor(own string) string {
	if own != "" {
		return own
	}
	if s.tenant != "" {
		return s.tenant
	}
	if s.personas != nil {
		return s.personas.Tenant
	}
	return ""
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

func garmClaim(kind, clearance, compartments, verbs, sets string) map[string]any {
	c := map[string]any{
		"clearance": canonicalClearance(orDefault(clearance, "CLEARANCE_INTERNAL")),
	}
	// Only when asked for. The verifier reads an absent `kind` as a principal
	// whose kind was never stated, which is exactly what these tokens have
	// always been.
	if kind != "" {
		c["kind"] = kind
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
