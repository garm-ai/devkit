package idp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const personasYAML = `
roles:
  support-agent:
    clearance: INTERNAL
    compartments: [pii-contact]
    verbs: [READ]
  payments-desk:
    clearance: RESTRICTED
    compartments: [financial]
    verbs: [READ, WRITE]
users:
  alice:
    subject: "user:alice"
    roles: [payments-desk, support-agent]
  bob:
    subject: "user:bob"
    roles: [support-agent]
agents:
  triage-bot:
    subject: "agent:triage-bot"
    roles: [support-agent]
    may_act_for: [bob]
`

func writePersonas(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "personas.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func personasFromYAML(t *testing.T, body string) *personas {
	t.Helper()
	p, err := loadPersonas(writePersonas(t, body))
	if err != nil {
		t.Fatalf("loading personas: %v", err)
	}
	return p
}

// Holding two roles gives you MORE. Acting for someone gives you LESS. They
// are opposite operations on the same token, and getting them the same way
// round would either strip authority from multi-role users or let delegation
// widen it.
func TestRolesUnionAndClearanceTakesTheHighest(t *testing.T) {
	p, err := loadPersonas(writePersonas(t, personasYAML))
	if err != nil {
		t.Fatalf("loadPersonas: %v", err)
	}

	a := p.expand(p.Users["alice"])
	// Canonical, not the file's spelling: the file says `RESTRICTED` because
	// a human writes it, and the token carries the enum name because a
	// verifier reads it.
	if a.Clearance != "CLEARANCE_RESTRICTED" {
		t.Errorf("clearance = %q; two roles must give the HIGHEST, not the last or "+
			"the lowest", a.Clearance)
	}
	if len(a.Compartments) != 2 {
		t.Errorf("compartments = %v; both roles' compartments must be present", a.Compartments)
	}
	if len(a.Verbs) != 2 {
		t.Errorf("verbs = %v; want READ and WRITE unioned", a.Verbs)
	}
}

// Who may act for whom is an IdP decision. garm folds a chain it is given and
// can only narrow it — it cannot know whether the delegation was permitted.
func TestDelegationEntitlementIsEnforced(t *testing.T) {
	p, err := loadPersonas(writePersonas(t, personasYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !p.mayActFor("triage-bot", "bob") {
		t.Error("triage-bot is listed as able to act for bob and was refused")
	}
	if p.mayActFor("triage-bot", "alice") {
		t.Error("triage-bot acted for alice, who is not in its may_act_for; a dev IdP " +
			"that mints any chain asked of it teaches that delegation is " +
			"unconstrained, which is the opposite of true")
	}
	if p.mayActFor("unknown-bot", "bob") {
		t.Error("an agent not in the file was allowed to act for someone")
	}
}

// A typo in an identity file is someone believing a principal has authority
// it does not have, discovered later as a denial nobody can explain.
func TestAFileThatNamesWhatItDoesNotDefineIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, body, wantIn string }{
		{
			name:   "undefined role",
			body:   "roles:\n  a: {clearance: INTERNAL}\nusers:\n  u: {subject: s, roles: [nope]}\n",
			wantIn: "nope",
		},
		{
			name:   "may_act_for an unknown user",
			body:   "roles:\n  a: {clearance: INTERNAL}\nagents:\n  bot: {subject: s, roles: [a], may_act_for: [ghost]}\n",
			wantIn: "ghost",
		},
		{
			name:   "a user claiming delegation entitlement",
			body:   "roles:\n  a: {clearance: INTERNAL}\nusers:\n  u: {subject: s, roles: [a], may_act_for: [u]}\n",
			wantIn: "may_act_for",
		},
		{
			name:   "an unknown key",
			body:   "roles:\n  a: {clearance: INTERNAL}\nusrs:\n  u: {subject: s}\n",
			wantIn: "usrs",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadPersonas(writePersonas(t, tc.body))
			if err == nil {
				t.Fatalf("accepted a file that should be refused")
			}
			if !contains(err.Error(), tc.wantIn) {
				t.Errorf("error does not name %q: %v", tc.wantIn, err)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Both mint paths must spell the claim the same way.
//
// They did not. The ?clearance= path defaulted to the enum name while the
// persona path copied the file verbatim, so the same logical clearance
// arrived as `CLEARANCE_RESTRICTED` down one path and `RESTRICTED` down the
// other. The verifier accepts both, so nothing failed — the cost was a wire
// contract with two spellings and a second verifier, written against dev
// tokens, learning the wrong one.
func TestBothMintPathsSpellClearanceTheSameWay(t *testing.T) {
	for _, in := range []string{"RESTRICTED", "CLEARANCE_RESTRICTED", "restricted", " Restricted "} {
		if got := canonicalClearance(in); got != "CLEARANCE_RESTRICTED" {
			t.Errorf("canonicalClearance(%q) = %q, want CLEARANCE_RESTRICTED", in, got)
		}
	}
	// An unrecognised value is passed through rather than guessed at, so the
	// verifier rejects it. Silently mapping a typo onto a real clearance is
	// how a principal ends up with authority nobody granted.
	if got := canonicalClearance("RESTRICTD"); got != "RESTRICTD" {
		t.Errorf("canonicalClearance(typo) = %q; a typo must reach the verifier as "+
			"itself and be refused, never be repaired into a clearance", got)
	}
}

// A clearance the file misspells is refused at load, for the same reason a
// role it does not define is: unchecked, the persona mints as PUBLIC and the
// denial surfaces much later as one nobody can explain.
func TestAMisspelledClearanceIsRefusedAtLoad(t *testing.T) {
	_, err := loadPersonas(writePersonas(t,
		"roles:\n  r: {clearance: RESTRICTD}\nusers:\n  u: {subject: s, roles: [r]}\n"))
	if err == nil {
		t.Fatal("a role with clearance RESTRICTD loaded; it ranks below PUBLIC and " +
			"would silently mint the weakest identity in the file")
	}
	if !strings.Contains(err.Error(), "RESTRICTD") {
		t.Errorf("error %q does not name the offending value", err)
	}
}

// KnownFields(true) means a key this struct does not declare is a hard error,
// which is the right default for an identity file — and the reason adding a
// key has to come with a test that the file still loads.
func TestAPersonasFileMayDeclareATenant(t *testing.T) {
	p := personasFromYAML(t, `
tenant: bank
roles:
  r: { clearance: INTERNAL, verbs: [READ] }
users:
  u: { subject: "employee:u", roles: [r], tenant: acme }
`)
	if p.Tenant != "bank" {
		t.Errorf("file tenant = %q, want bank", p.Tenant)
	}
	if got := p.Users["u"].Tenant; got != "acme" {
		t.Errorf("user tenant = %q, want acme", got)
	}
}
