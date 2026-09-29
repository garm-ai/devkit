package idp

import (
	"os"
	"path/filepath"
	"testing"
)

// The shipped example must load, because it is the first thing anyone runs.
//
// `mise run idp` points at it and the README quotes it. An example that fails
// to parse is worse than no example: it reads as the tool being broken rather
// than the file, and it is the one file here nobody re-reads before trusting.
func TestTheShippedExamplePersonasLoad(t *testing.T) {
	path := filepath.Join("..", "examples", "personas.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the example personas file is missing: %v", err)
	}
	p, err := loadPersonas(path)
	if err != nil {
		t.Fatalf("examples/personas.yaml does not load: %v", err)
	}

	// The example exists to demonstrate delegation, which needs an entitled
	// pair and an unentitled one. Without both, the interesting refusal is
	// unreachable and the file quietly stops teaching the thing it is for.
	var entitled, unentitled int
	for agent := range p.Agents {
		for user := range p.Users {
			if p.mayActFor(agent, user) {
				entitled++
			} else {
				unentitled++
			}
		}
	}
	if entitled == 0 {
		t.Error("no agent may act for any user; the delegation demo cannot be run")
	}
	if unentitled == 0 {
		t.Error("every agent may act for every user, so `?as=` can never be refused " +
			"and the entitlement check looks like it does nothing")
	}
}
