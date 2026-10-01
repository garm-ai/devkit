package idp

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Personas are a FILE, not a store, and that is the decision worth stating.
//
// Everything a management API would hold is either a credential (which should
// not persist — the signing key is already ephemeral on purpose) or a small
// piece of configuration. Configuration in this project lives in files that a
// pull request can argue about: garm.yaml, app.garm.yaml, the proto
// annotations themselves. A mutable user store would be the first
// runtime-mutable state in the whole system, and it could not be
// code-reviewed, diffed, or used as a test fixture.
//
// There is a second reason, less technical and more important. A dev IdP with
// a CRUD API starts to look like a product; someone points a staging
// environment at it. The loopback check stops that today, and a management
// API is an invitation to remove it.
type personas struct {
	// Tenant is the tenant every persona in this file belongs to unless it
	// says otherwise.
	//
	// It lives here rather than behind a flag default because a tenant is a
	// property of the population this file declares, not of the process
	// serving it — the next personas file somebody writes is not the bank's,
	// and a constant in the binary would be quietly wrong for it.
	Tenant string             `yaml:"tenant"`
	Roles  map[string]role    `yaml:"roles"`
	Users  map[string]persona `yaml:"users"`
	Agents map[string]persona `yaml:"agents"`
}

// role is a BUNDLE of claims, and bundling is an identity provider's job.
//
// garm never sees a role. It receives the clearance, compartments and verbs a
// role expands to — which is exactly how a real IdP works, and why mapping
// Entra App Roles onto these fields belongs in step 1 rather than in the
// chain. A role reaching the policy chain would be a second vocabulary for
// answering the same question.
type role struct {
	Clearance    string   `yaml:"clearance" json:"clearance"`
	Compartments []string `yaml:"compartments" json:"compartments"`
	Verbs        []string `yaml:"verbs" json:"verbs"`
	ToolSets     []string `yaml:"tool_sets" json:"tool_sets"`
}

// persona carries json tags beside the yaml ones because GET /personas
// serves it. Without them the endpoint encoded Go field names — `Subject`,
// `MayActFor` — and every client that read the YAML spelling, including
// this IdP's own picker page, saw a persona with no roles.
type persona struct {
	// Subject is what lands in `sub` and therefore in every ledger row. It
	// is separate from the map key on purpose: the key is the handle you
	// type, the subject is the identity that must stay stable when the
	// handle changes. Real IdPs emit opaque subjects, and a dev tool that
	// hid that distinction would teach people to key dashboards on names.
	Subject string   `yaml:"subject" json:"subject"`
	Roles   []string `yaml:"roles" json:"roles"`

	// MayActFor lists the users this agent is entitled to act for. It is
	// enforced when minting and garm NEVER sees it: garm folds a delegation
	// chain it is given and can only narrow it, but it cannot know whether
	// the delegation was permitted. The IdP asserts that by agreeing to
	// sign. A dev IdP that minted any chain asked of it would teach that
	// delegation is unconstrained, which is the opposite of true.
	MayActFor []string `yaml:"may_act_for" json:"may_act_for"`

	// Tenant overrides the file's for this identity. Two personas in two
	// tenants calling the same tool is the only way to demonstrate that
	// confinement works at all, and a file-wide value could not express it.
	Tenant string `yaml:"tenant" json:"tenant"`
}

func loadPersonas(path string) (*personas, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading personas: %w", err)
	}
	var p personas
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a typo'd key is a misconfigured identity, not a warning
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parsing personas: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// validate refuses a file that names things it does not define.
//
// A role or user that does not exist is a typo, and a typo in an identity
// file is someone believing a principal has authority it does not have —
// discovered later, as a denial nobody can explain.
func (p *personas) validate() error {
	// A clearance this file does not spell correctly is the same failure as
	// a role it does not define: someone believing a principal has authority
	// it does not have. Unchecked, `RESTRICTD` ranks below every real
	// clearance and the persona silently mints as PUBLIC.
	for name, r := range p.Roles {
		if clearanceRank(r.Clearance) == 0 {
			return fmt.Errorf("role %q has clearance %q, which is not one of "+
				"PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED", name, r.Clearance)
		}
	}
	for name, u := range p.Users {
		if err := p.checkRoles("user", name, u.Roles); err != nil {
			return err
		}
		if len(u.MayActFor) > 0 {
			return fmt.Errorf("user %q declares may_act_for; only agents act for someone", name)
		}
	}
	for name, a := range p.Agents {
		if err := p.checkRoles("agent", name, a.Roles); err != nil {
			return err
		}
		for _, who := range a.MayActFor {
			if _, ok := p.Users[who]; !ok {
				return fmt.Errorf("agent %q may_act_for %q, which is not a user in this file", name, who)
			}
		}
	}
	return nil
}

func (p *personas) checkRoles(kind, name string, roles []string) error {
	for _, r := range roles {
		if _, ok := p.Roles[r]; !ok {
			have := make([]string, 0, len(p.Roles))
			for k := range p.Roles {
				have = append(have, k)
			}
			sort.Strings(have)
			return fmt.Errorf("%s %q has role %q, which this file does not define; it defines %s",
				kind, name, r, strings.Join(have, ", "))
		}
	}
	return nil
}

// authority is the claims a persona's roles expand to.
type authority struct {
	Clearance    string
	Compartments []string
	Verbs        []string
	ToolSets     []string
}

// expand unions a persona's roles.
//
// UNION, not intersection, and the difference matters. Holding two roles
// gives you MORE — that is a union. Acting on behalf of someone gives you
// LESS — that is the intersection garmauth.Fold already performs across the
// chain. Same token, two opposite operations; conflating them would either
// strip authority from multi-role users or let delegation widen it.
//
// Clearance takes the HIGHEST of the roles for the same reason.
func (p *personas) expand(who persona) authority {
	var a authority
	compartments := map[string]bool{}
	verbs := map[string]bool{}
	sets := map[string]bool{}

	for _, name := range who.Roles {
		r := p.Roles[name]
		if clearanceRank(r.Clearance) > clearanceRank(a.Clearance) {
			a.Clearance = r.Clearance
		}
		for _, c := range r.Compartments {
			compartments[c] = true
		}
		for _, v := range r.Verbs {
			verbs[v] = true
		}
		for _, s := range r.ToolSets {
			sets[s] = true
		}
	}
	a.Compartments = sortedSet(compartments)
	a.Verbs = sortedSet(verbs)
	a.ToolSets = sortedSet(sets)
	if a.Clearance == "" {
		// No roles at all. PUBLIC is the floor, not a default worth
		// inferring anything from.
		a.Clearance = "CLEARANCE_PUBLIC"
	}
	a.Clearance = canonicalClearance(a.Clearance)
	return a
}

// clearanceRank orders clearances without importing garm's enum — this
// repository must not depend on the product compiling. 0 means "not a
// clearance"; loadPersonas refuses those, so it never reaches expand.
func clearanceRank(s string) int {
	switch bareClearance(s) {
	case "PUBLIC":
		return 10
	case "INTERNAL":
		return 20
	case "CONFIDENTIAL":
		return 30
	case "RESTRICTED":
		return 40
	}
	return 0
}

func bareClearance(s string) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "CLEARANCE_")
}

// canonicalClearance is the spelling that goes on the wire, and there is
// exactly one.
//
// The personas file is written by a human and takes the friendly form
// (`clearance: RESTRICTED`); the ?clearance= query takes whatever it is
// given. Both used to reach the token body verbatim, so the same claim
// arrived spelled two ways depending on which path minted it. Nothing broke,
// because the verifier happens to accept both — which is precisely why it
// went unnoticed, and why a second verifier written against dev tokens would
// have been written against a form that is not the enum.
//
// A token is a contract. It carries the enum name, always, whatever was
// typed. An empty or unrecognised value is returned unchanged for the
// verifier to reject: guessing here would turn a typo into a silent
// downgrade.
func canonicalClearance(s string) string {
	if clearanceRank(s) == 0 {
		return s
	}
	return "CLEARANCE_" + bareClearance(s)
}

// canonicalKind is the spelling of a principal kind that goes on the wire,
// and it REFUSES what it does not recognise.
//
// The verifier maps `garm.kind` onto a PRINCIPAL_KIND_* name and returns
// nothing at all for a value it does not know, with no error and nothing told
// to the caller. A misspelled kind and an absent one are therefore the same
// token downstream: `?kind=srvice` verifies, carries no kind, and is refused
// much later by a service saying the caller is not a service — and nothing in
// that message points at the mint URL. This is the last place that can still
// tell "no kind was asked for" from "a kind was asked for and misspelled", so
// it is where the two are told apart.
//
// UNSPECIFIED is refused for the same reason rather than passed through: it
// is the value the verifier reads as no kind at all.
//
// The returned spelling is bare and upper-case — USER, AGENT, SERVICE — which
// is what the persona path already mints, so one claim has one form however
// it was asked for.
func canonicalKind(s string) (string, error) {
	switch bare := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "PRINCIPAL_KIND_"); bare {
	case "USER", "AGENT", "SERVICE":
		return bare, nil
	default:
		return "", fmt.Errorf("kind %q is not one of user, agent, service", s)
	}
}

func sortedSet(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// mayActFor reports whether agent is entitled to act for user.
func (p *personas) mayActFor(agent, user string) bool {
	a, ok := p.Agents[agent]
	if !ok {
		return false
	}
	for _, who := range a.MayActFor {
		if who == user {
			return true
		}
	}
	return false
}
