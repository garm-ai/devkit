package main

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/garm-ai/devkit/idp"
)

func newIdPCmd() *cobra.Command {
	var addr string
	var audience string
	var ttl time.Duration
	var personasPath string
	var garmURL string
	var tenant string

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
			return idp.Serve(cmd.Context(), idp.Config{
				Addr:         addr,
				Audience:     audience,
				TTL:          ttl,
				GarmURL:      garmURL,
				Tenant:       tenant,
				PersonasPath: personasPath,
				// The banner is this command's greeting to a developer at a
				// terminal, not the server's, so it is printed from here —
				// once the address is actually bound.
				OnListen: func(bound string) { banner(cmd.ErrOrStderr(), bound, audience) },
			})
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:7450", "loopback address to serve on")
	cmd.Flags().StringVar(&audience, "audience", "garm", "the aud minted tokens carry")
	cmd.Flags().DurationVar(&ttl, "ttl", time.Hour, "how long minted tokens are valid")
	cmd.Flags().StringVar(&garmURL, "garm-url", "http://127.0.0.1:7440",
		"the tool plane the UI asks what each principal can see")
	cmd.Flags().StringVar(&personasPath, "personas", "",
		"a personas file defining roles, users, agents and who may act for whom")
	cmd.Flags().StringVar(&tenant, "tenant", "",
		"Tenant every minted token names, overriding the personas file's. "+
			"Everything downstream refuses a token with no tenant at all")
	return cmd
}

// banner says, once the address is bound, what this process is and how to
// ask it for a token. Stderr, so `garmdev idp > tokens` is still useful.
func banner(w io.Writer, bound, audience string) {
	base := "http://" + bound
	fmt.Fprintf(w, `garmdev idp — DEVELOPMENT ONLY, mints any identity asked of it

  jwks_url  %s/.well-known/jwks.json
  issuer    %s
  audience  %s

  UI:       %s
  a token:  curl -s '%s/token?user=alice'
  delegated: curl -s '%s/token?user=bob&as=triage-bot'
  a service: curl -s '%s/token?kind=service&sub=service:agentd&tenant=bank'

`, base, idp.DevIssuer, audience, base, base, base, base)
}
