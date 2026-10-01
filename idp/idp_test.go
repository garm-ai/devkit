package idp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// claimsOf verifies a minted token against the served key set and returns
// its body.
//
// It checks the SIGNATURE and reads the CLAIMS, and stops deliberately short
// of building a Principal. Folding the act chain, resolving compartments and
// mapping the clearance enum are the verifier's job, and the verifier lives
// in garmd, where the request path is. This repository must not import it:
// this binary mints tokens, and a module that can assert any identity must
// never appear in the dependency graph of one that decides what an identity
// may do.
//
// The hazard that leaves is the two halves drifting apart silently, until
// every dev token stops verifying for a reason nobody can see. It is closed
// from the other side rather than here — `mise run goldens` writes a token
// and key set into testdata/, garmd's authn tests read them, and a change to
// the body below fails garmd's CI instead of somebody's afternoon.
func claimsOf(t *testing.T, srv *httptest.Server, token string) map[string]any {
	t.Helper()
	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatalf("decoding the key set: %v", err)
	}
	if len(set.Keys) == 0 {
		t.Fatal("the key set is empty, so nothing could verify a token")
	}
	sig, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parsing the token: %v", err)
	}
	payload, err := sig.Verify(set.Keys[0])
	if err != nil {
		t.Fatalf("a token the dev IdP minted did not verify against the key it "+
			"serves: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("the token body is not JSON: %v", err)
	}
	return body
}

// garmClaimIn reads the `garm` claim, which is where every authority field
// lives. Named to avoid colliding with garmClaim, which builds it.
func garmClaimIn(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	c, ok := body["garm"].(map[string]any)
	if !ok {
		t.Fatalf("no garm claim in %v", body)
	}
	return c
}

func startIDP(t *testing.T) *httptest.Server {
	t.Helper()
	h, err := New(Config{Audience: "garm"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func mint(t *testing.T, srv *httptest.Server, query string) string {
	t.Helper()
	resp, err := http.Get(srv.URL + "/token?" + query)
	if err != nil {
		t.Fatalf("GET /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /token: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading token: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

func TestAMintedTokenIsSignedByTheKeyItServes(t *testing.T) {
	srv := startIDP(t)
	token := mint(t, srv,
		"sub=alice&clearance=CLEARANCE_CONFIDENTIAL&compartments=financial&verbs=VERB_READ")

	body := claimsOf(t, srv, token)
	if body["sub"] != "alice" {
		t.Errorf("sub = %v, want alice", body["sub"])
	}
	if body["iss"] != DevIssuer {
		t.Errorf("iss = %v, want %s", body["iss"], DevIssuer)
	}
	if body["aud"] != "garm" {
		t.Errorf("aud = %v, want garm", body["aud"])
	}
	if got := garmClaimIn(t, body)["clearance"]; got != "CLEARANCE_CONFIDENTIAL" {
		t.Errorf("clearance = %v, want CLEARANCE_CONFIDENTIAL", got)
	}
}

// The act chain carries BOTH identities, which is what makes narrowing
// possible on the far side.
//
// What this does NOT assert is that an INTERNAL agent acting for a
// CONFIDENTIAL user comes out INTERNAL. That is folding, it happens in the
// verifier, and asserting it here would mean this repository owned a claim
// about code it cannot see. garmd owns it, against the golden this
// repository emits.
func TestAnActChainCarriesBothIdentities(t *testing.T) {
	srv := startIDP(t)
	token := mint(t, srv,
		"sub=alice&clearance=CLEARANCE_CONFIDENTIAL&compartments=financial&verbs=VERB_READ"+
			"&act=agent-1&act_clearance=CLEARANCE_INTERNAL")

	body := claimsOf(t, srv, token)
	if got := garmClaimIn(t, body)["clearance"]; got != "CLEARANCE_CONFIDENTIAL" {
		t.Errorf("the subject's own clearance = %v, want CONFIDENTIAL", got)
	}
	act, ok := body["act"].(map[string]any)
	if !ok {
		t.Fatalf("no act chain in %v", body)
	}
	if act["sub"] != "agent-1" {
		t.Errorf("act.sub = %v, want agent-1", act["sub"])
	}
	ac, ok := act["garm"].(map[string]any)
	if !ok {
		t.Fatalf("the act chain carries no garm claim, so the verifier would have "+
			"nothing to narrow with: %v", act)
	}
	if ac["clearance"] != "CLEARANCE_INTERNAL" {
		t.Errorf("act clearance = %v, want INTERNAL", ac["clearance"])
	}
}

// A token minter that anyone on the network can reach is a way to mint any
// identity. It binds loopback or it does not bind.
func TestTheIDPRefusesANonLoopbackBind(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:7450", ":7450", "10.0.0.5:7450", "[::]:7450"} {
		if err := checkLoopback(addr); err == nil {
			t.Errorf("%s was accepted; a dev token minter must not be reachable off "+
				"this machine — it will mint any identity anyone asks for", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:7450", "localhost:7450", "[::1]:7450"} {
		if err := checkLoopback(addr); err != nil {
			t.Errorf("%s was refused: %v", addr, err)
		}
	}
}

func TestJWKSServesAKeyWithAKid(t *testing.T) {
	srv := startIDP(t)
	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	if !strings.Contains(body, `"kid"`) {
		t.Errorf("the key set publishes no kid, so no token can name its key: %s", body)
	}
}

func startIDPWithPersonas(t *testing.T) *httptest.Server {
	t.Helper()
	p, err := loadPersonas(writePersonas(t, personasYAML))
	if err != nil {
		t.Fatalf("loadPersonas: %v", err)
	}
	h, err := New(Config{Audience: "garm", Personas: p})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// A persona's roles must reach the token as the authority they expand to.
// Roles themselves never appear: garm receives clearance, compartments and
// verbs, never a role name, because a role reaching the policy chain would be
// a second vocabulary for answering the same question.
func TestAPersonaMintsTheAuthorityItsRolesExpandTo(t *testing.T) {
	srv := startIDPWithPersonas(t)
	body := claimsOf(t, srv, mint(t, srv, "user=alice"))

	if body["sub"] != "user:alice" {
		t.Errorf("sub = %v, want the file's subject rather than the handle", body["sub"])
	}
	c := garmClaimIn(t, body)
	if c["clearance"] != "CLEARANCE_RESTRICTED" {
		t.Errorf("clearance = %v; alice holds two roles and must get the highest", c["clearance"])
	}
	if c["kind"] != "USER" {
		t.Errorf("kind = %v, want USER", c["kind"])
	}
	if _, leaked := c["roles"]; leaked {
		t.Error("the token carries role names; garm must never see a role, only what " +
			"it expands to")
	}
}

// The delegation round trip: entitled, minted, both halves present.
//
// Narrowing is asserted in garmd against the golden, for the reason given on
// TestAnActChainCarriesBothIdentities.
func TestADelegatedPersonaTokenCarriesTheAgentAsActor(t *testing.T) {
	srv := startIDPWithPersonas(t)

	// bob is support-agent (INTERNAL); triage-bot may act for bob.
	direct := claimsOf(t, srv, mint(t, srv, "user=bob"))
	delegated := claimsOf(t, srv, mint(t, srv, "user=bob&as=triage-bot"))

	if delegated["sub"] != direct["sub"] {
		t.Errorf("delegation changed the subject: %v vs %v", delegated["sub"], direct["sub"])
	}
	act, ok := delegated["act"].(map[string]any)
	if !ok {
		t.Fatalf("no act chain in the delegated token: %v", delegated)
	}
	if act["sub"] != "agent:triage-bot" {
		t.Errorf("act.sub = %v, want the agent's subject", act["sub"])
	}
	// The subject's own claim is untouched by delegation. A minter that
	// pre-narrowed would destroy the information the verifier needs to fold,
	// and would hide whose authority was actually being exercised.
	if garmClaimIn(t, delegated)["clearance"] != garmClaimIn(t, direct)["clearance"] {
		t.Error("minting narrowed the subject's own clearance; folding belongs to the " +
			"verifier, which needs both halves to do it")
	}
	if got := garmClaimIn(t, delegated)["kind"]; got != "USER" {
		t.Errorf("kind = %v; the authority being exercised is bob's, and the agent "+
			"exercising it is the actor", got)
	}
}

// The entitlement is enforced at MINT time, because garm cannot enforce it at
// verify time — it folds what it is given.
func TestMintingRefusesAnUnentitledDelegation(t *testing.T) {
	srv := startIDPWithPersonas(t)

	resp, err := http.Get(srv.URL + "/token?user=alice&as=triage-bot")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d; triage-bot may act for bob only, and minting the chain "+
			"anyway would teach that delegation is unconstrained", resp.StatusCode)
	}
}

func TestPersonasAreListedButNotWritable(t *testing.T) {
	srv := startIDPWithPersonas(t)

	resp, err := http.Get(srv.URL + "/personas")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /personas: status %d", resp.StatusCode)
	}

	// There is deliberately no create/update/delete: management is editing
	// the file, which keeps personas reviewable and diffable.
	post, err := http.Post(srv.URL+"/personas", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer post.Body.Close()
	body, _ := io.ReadAll(post.Body)
	if post.StatusCode == http.StatusCreated || strings.Contains(string(body), "created") {
		t.Error("POST /personas appears to have created something; personas are a file, " +
			"not a store, and a CRUD API is how a dev IdP turns into a product")
	}
}

// GET /personas speaks the YAML's vocabulary, not Go's. The struct carried
// yaml tags only, so the endpoint encoded `Subject`, `Roles`, `MayActFor`,
// and every reader written against the file's spelling — the picker page in
// this very binary reads `u.roles` — saw personas with no roles at all.
func TestPersonasAreListedUnderTheirYAMLKeys(t *testing.T) {
	srv := startIDPWithPersonas(t)
	resp, err := http.Get(srv.URL + "/personas")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	for _, goName := range []string{`"Subject"`, `"Roles"`, `"MayActFor"`, `"Tenant"`, `"Clearance"`, `"ToolSets"`} {
		if strings.Contains(string(raw), goName) {
			t.Errorf("GET /personas encodes the Go field name %s", goName)
		}
	}

	var body struct {
		Roles  map[string]map[string]json.RawMessage `json:"roles"`
		Users  map[string]map[string]json.RawMessage `json:"users"`
		Agents map[string]map[string]json.RawMessage `json:"agents"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("GET /personas is not the expected shape: %v\n%s", err, raw)
	}
	if len(body.Users) == 0 || len(body.Agents) == 0 || len(body.Roles) == 0 {
		t.Fatalf("the example file has users, agents and roles; got %d/%d/%d", len(body.Users), len(body.Agents), len(body.Roles))
	}
	for kind, set := range map[string]map[string]map[string]json.RawMessage{"user": body.Users, "agent": body.Agents, "role": body.Roles} {
		for name, fields := range set {
			for key := range fields {
				if key != strings.ToLower(key) {
					t.Errorf("%s %q has key %q; keys are lower-case snake_case like the YAML", kind, name, key)
				}
			}
		}
	}
	for name, u := range body.Users {
		for _, want := range []string{"subject", "roles", "may_act_for", "tenant"} {
			if _, ok := u[want]; !ok {
				t.Errorf("user %q has no %q key", name, want)
			}
		}
	}
	for name, a := range body.Agents {
		if _, ok := a["may_act_for"]; !ok {
			t.Errorf("agent %q has no may_act_for key", name)
		}
	}
	for name, r := range body.Roles {
		for _, want := range []string{"clearance", "compartments", "verbs", "tool_sets"} {
			if _, ok := r[want]; !ok {
				t.Errorf("role %q has no %q key", name, want)
			}
		}
	}
}

// The page must reference only its own origin. It is served by a tool whose
// whole premise is that it works on a laptop with nothing else running, and a
// CDN reference would make the dev UI silently depend on the internet.
func TestTheUIFetchesNothingFromTheInternet(t *testing.T) {
	srv := startIDPWithPersonas(t)

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, host := range []string{"https://", "http://", "//cdn", "unpkg", "jsdelivr"} {
		if strings.Contains(string(body), host) {
			t.Errorf("the UI references %q; it must work with no network at all", host)
		}
	}
}

// The proxy reuses the minting path rather than reimplementing it, so the
// entitlement check applies to it too. If the two ever drifted, this is the
// check that would be missing from one of them.
func TestTheToolsProxyEnforcesDelegationEntitlement(t *testing.T) {
	srv := startIDPWithPersonas(t)

	resp, err := http.Get(srv.URL + "/tools?user=alice&as=triage-bot")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d; the proxy must refuse an unentitled chain before it "+
			"reaches garm, exactly as /token does", resp.StatusCode)
	}
}

// garm being absent is a normal state for a dev tool, and must read as one.
func TestTheProxySaysSoWhenGarmIsNotRunning(t *testing.T) {
	p, err := loadPersonas(writePersonas(t, personasYAML))
	if err != nil {
		t.Fatal(err)
	}
	// A port nothing is listening on.
	h, err := New(Config{Audience: "garm", Personas: p, GarmURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tools?user=alice")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "could not reach garm") {
		t.Errorf("an unreachable garm produced %q; it should say so plainly rather "+
			"than look like an empty catalogue", string(body))
	}
}

func newTestServer(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// A dev token has to name a tenant, because everything downstream of it
// refuses one that does not.
//
// The STS reads `tenant` off a subject token and refuses to mint when it is
// empty — confinement to a tenant's own data depends on it flowing from a
// verified token, so an empty one is a confinement failure rather than a
// cosmetic gap. A dev IdP that omitted it would make every exchange fail with
// an access_denied that says nothing about tenants.
func TestAPersonaTokenNamesTheTenantTheFileDeclares(t *testing.T) {
	srv := newTestServer(t, Config{
		Audience: "garm",
		Personas: personasFromYAML(t, `
tenant: bank
roles:
  support-desk: { clearance: INTERNAL, compartments: [pii-contact], verbs: [READ] }
users:
  jdoe: { subject: "employee:jdoe", roles: [support-desk] }
`),
	})

	claims := claimsOf(t, srv, mint(t, srv, "user=jdoe"))
	if got := claims["tenant"]; got != "bank" {
		t.Errorf("tenant = %v, want bank", got)
	}
}

// The flag wins over the file, so one personas file serves two environments.
func TestTheTenantFlagOverridesTheFile(t *testing.T) {
	srv := newTestServer(t, Config{
		Audience: "garm",
		Tenant:   "acme",
		Personas: personasFromYAML(t, `
tenant: bank
roles:
  support-desk: { clearance: INTERNAL, compartments: [pii-contact], verbs: [READ] }
users:
  jdoe: { subject: "employee:jdoe", roles: [support-desk] }
`),
	})

	claims := claimsOf(t, srv, mint(t, srv, "user=jdoe"))
	if got := claims["tenant"]; got != "acme" {
		t.Errorf("tenant = %v, want acme — --tenant must win over the file", got)
	}
}

// And a persona wins over both, because a multi-tenant demo is the whole
// reason a tenant claim is interesting: two personas in two tenants, calling
// the same tool, must not see each other's rows.
func TestAPersonaCanNameItsOwnTenant(t *testing.T) {
	srv := newTestServer(t, Config{
		Audience: "garm",
		Personas: personasFromYAML(t, `
tenant: bank
roles:
  support-desk: { clearance: INTERNAL, compartments: [pii-contact], verbs: [READ] }
users:
  jdoe:  { subject: "employee:jdoe", roles: [support-desk] }
  zhang: { subject: "employee:zhang", roles: [support-desk], tenant: acme }
`),
	})

	if got := claimsOf(t, srv, mint(t, srv, "user=jdoe"))["tenant"]; got != "bank" {
		t.Errorf("jdoe tenant = %v, want bank", got)
	}
	if got := claimsOf(t, srv, mint(t, srv, "user=zhang"))["tenant"]; got != "acme" {
		t.Errorf("zhang tenant = %v, want acme", got)
	}
}

// The delegated form carries it too: the tenant belongs to the SUBJECT, and
// an agent acting for someone does not change whose data is in scope.
func TestADelegatedPersonaTokenKeepsTheSubjectsTenant(t *testing.T) {
	srv := newTestServer(t, Config{
		Audience: "garm",
		Personas: personasFromYAML(t, `
tenant: bank
roles:
  support-desk: { clearance: INTERNAL, compartments: [pii-contact], verbs: [READ] }
users:
  jdoe: { subject: "employee:jdoe", roles: [support-desk] }
agents:
  assistant: { subject: "agent:assistant", roles: [support-desk], may_act_for: [jdoe] }
`),
	})

	claims := claimsOf(t, srv, mint(t, srv, "user=jdoe&as=assistant"))
	if got := claims["tenant"]; got != "bank" {
		t.Errorf("delegated tenant = %v, want bank", got)
	}
}

// Nothing configured means no claim at all, not an empty one. An empty
// string is a value the STS would read and refuse; an absent key is the
// honest shape for "this file never said", and it is what the ad-hoc form
// has always produced when ?tenant= is not given.
func TestATokenWithNoTenantConfiguredOmitsTheClaim(t *testing.T) {
	srv := newTestServer(t, Config{
		Audience: "garm",
		Personas: personasFromYAML(t, `
roles:
  support-desk: { clearance: INTERNAL, compartments: [pii-contact], verbs: [READ] }
users:
  jdoe: { subject: "employee:jdoe", roles: [support-desk] }
`),
	})

	claims := claimsOf(t, srv, mint(t, srv, "user=jdoe"))
	if got, present := claims["tenant"]; present {
		t.Errorf("tenant = %q; with nothing configured the claim must be absent, "+
			"not stamped empty", got)
	}
}

// tokenStatus asks for a token and returns the status and body rather than
// failing on a non-200, which is what the refusals below assert.
func tokenStatus(t *testing.T, srv *httptest.Server, query string) (int, string) {
	t.Helper()
	resp, err := http.Get(srv.URL + "/token?" + query)
	if err != nil {
		t.Fatalf("GET /token: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	return resp.StatusCode, string(raw)
}

// A service principal is a thing the platform needs and this IdP could not
// mint: a component acting as ITSELF rather than for a person. Without a kind
// on the token every identity minted here is implicitly a person, so no
// service principal existed anywhere.
func TestAServiceTokenNamesTheServiceKind(t *testing.T) {
	srv := startIDP(t)
	body := claimsOf(t, srv, mint(t, srv,
		"kind=service&sub=service:agentd&tenant=bank&verbs=VERB_READ,VERB_WRITE"))

	if body["sub"] != "service:agentd" {
		t.Errorf("sub = %v, want service:agentd", body["sub"])
	}
	if got := garmClaimIn(t, body)["kind"]; got != "SERVICE" {
		t.Errorf("kind = %v, want SERVICE; garmd reads garm.kind and maps it onto "+
			"PRINCIPAL_KIND_SERVICE", got)
	}
	// A runner's agent chain is added per call by the platform, not baked
	// into its identity. A service token carrying one would make every call
	// it ever makes look delegated.
	if _, present := body["act"]; present {
		t.Errorf("a service token carries an act chain: %v", body["act"])
	}
	if got := body["tenant"]; got != "bank" {
		t.Errorf("tenant = %v, want bank", got)
	}
}

// The spellings garmd accepts, accepted here too, and all canonicalised to
// the one form the persona path already mints.
func TestEveryAcceptedKindSpellingMintsTheEnumName(t *testing.T) {
	srv := startIDP(t)
	for in, want := range map[string]string{
		"service":                "SERVICE",
		"SERVICE":                "SERVICE",
		"PRINCIPAL_KIND_SERVICE": "SERVICE",
		" Service ":              "SERVICE",
		"user":                   "USER",
		"agent":                  "AGENT",
	} {
		body := claimsOf(t, srv, mint(t, srv, "kind="+url.QueryEscape(in)+"&sub=s&tenant=bank"))
		if got := garmClaimIn(t, body)["kind"]; got != want {
			t.Errorf("kind=%q minted %v, want %s", in, got, want)
		}
	}
}

// The property every existing caller depends on: asking for no kind mints
// exactly what it minted before there was one. An absent kind is how garmd
// has always read these tokens, and stamping one by default would change the
// principal every persona and every ad-hoc token resolves to.
func TestATokenWithNoKindRequestedCarriesNoKindClaim(t *testing.T) {
	srv := startIDP(t)
	body := claimsOf(t, srv, mint(t, srv, "sub=alice&clearance=CLEARANCE_CONFIDENTIAL"))
	if got, present := garmClaimIn(t, body)["kind"]; present {
		t.Errorf("kind = %q; with no kind asked for the claim must be absent, not "+
			"defaulted — every caller that predates this parameter relies on it", got)
	}
}

// The check this IdP exists to make, because nothing downstream can.
//
// A verifier that normalises an unrecognised kind to the empty string cannot
// tell a typo from a token that asked for no kind at all — and garm's does
// exactly that. So the identity is accepted, is simply not a service, and is
// refused later by whatever required one, in a message that points at the call
// rather than at the mint. This is the last place that can still tell the two
// apart, which is why the refusal belongs here.
func TestAnUnrecognisedKindIsRefusedRatherThanPassedThrough(t *testing.T) {
	srv := startIDP(t)
	for _, bad := range []string{"srvice", "PRINCIPAL_KIND_UNSPECIFIED", "UNSPECIFIED", "workflow"} {
		status, body := tokenStatus(t, srv, "kind="+url.QueryEscape(bad)+"&sub=s&tenant=bank")
		if status != http.StatusBadRequest {
			t.Errorf("kind=%q minted with status %d; a typo must not quietly produce a "+
				"token with no kind at all", bad, status)
			continue
		}
		if !strings.Contains(body, bad) {
			t.Errorf("the refusal of kind=%q does not name the value: %s", bad, body)
		}
	}
}

// A service calls on its OWN behalf; that is what distinguishes it from an
// agent. The chain belongs on the call, not in the identity.
func TestAServiceTokenIsRefusedAnActChain(t *testing.T) {
	srv := startIDP(t)
	status, body := tokenStatus(t, srv, "kind=service&sub=service:agentd&tenant=bank&act=user:alice")
	if status != http.StatusBadRequest {
		t.Fatalf("status %d; a service token with a delegation chain baked in would "+
			"make every call it makes look delegated", status)
	}
	if !strings.Contains(body, "act") {
		t.Errorf("the refusal does not name the act chain: %s", body)
	}
}

// No tenant means no tenant claim, and the STS refuses to exchange a token
// without one — the bug this repository already fixed for personas. A service
// principal reaches the same wall, so it is refused at mint time where the
// message can still say why.
func TestAServiceTokenMustNameATenant(t *testing.T) {
	bare := startIDP(t)
	status, body := tokenStatus(t, bare, "kind=service&sub=service:agentd")
	if status != http.StatusBadRequest {
		t.Fatalf("status %d; a service token with no tenant verifies and then fails "+
			"every exchange with an access_denied that says nothing about tenants", status)
	}
	if !strings.Contains(body, "tenant") {
		t.Errorf("the refusal does not name the tenant: %s", body)
	}

	// Configured once for the process, it needs no query parameter: the same
	// order of precedence the persona path uses.
	configured := newTestServer(t, Config{Audience: "garm", Tenant: "acme"})
	claims := claimsOf(t, configured, mint(t, configured, "kind=service&sub=service:agentd"))
	if got := claims["tenant"]; got != "acme" {
		t.Errorf("tenant = %v, want acme from --tenant", got)
	}
}
