// Command garmdev is the garm development toolchain: things you run on a
// laptop or in CI, never in a request path.
//
// # Why this is its own repository
//
// It mints tokens. A binary that can mint tokens can assert any identity —
// any clearance, any compartment, any delegation chain — and "dev mode" is
// precisely the kind of switch that ends up on in a hurry somewhere it
// should not be.
//
// Keeping it out of `garm` is therefore not tidiness. `garm` is the CLI that
// lands on every developer machine and every enterprise build host; a token
// minter inside it is a token minter everywhere. Here, minting requires
// deliberately fetching a module whose name says what it is, and the
// `require` line is the audit trail.
//
// The monorepo enforced the same separation with a cross-GOOS `go list -deps`
// test. A repository boundary is strictly stronger: crossing it means adding
// `require github.com/garm-ai/devkit` to something in the request path, which
// is one grep in CI and visible in any review. garmd and garm both assert it.
//
// The consequence, and it is load-bearing: nothing here may import the
// verifier. The token body is written as plain JSON and this binary knows
// nothing about the types that will read it.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/garm-ai/devkit/internal/idp"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "garmdev:", err)
		os.Exit(1)
	}
}

// newRootCmd builds the command tree. Tests drive this rather than main, so
// wiring is checkable without a process boundary.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "garmdev",
		Short: "garm development toolchain",
		Long: "garmdev is the development half of garm. It never runs in production\n" +
			"and deliberately does not import the product, so it keeps working when\n" +
			"the tree does not.",
		SilenceUsage: true,
		// Errors are printed by main with the binary name, once. Cobra
		// printing them too would double every failure.
		SilenceErrors: true,
		// Bare `garmdev` is a mistake, not a request for the default
		// subcommand — there is no sensible default for a tool that mints
		// identities.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return fmt.Errorf("a subcommand is required; see `garmdev --help`")
		},
	}
	root.AddCommand(idp.Command())
	return root
}
