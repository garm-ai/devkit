# Known gaps

## Drift between the token body and the verifier is not yet caught

This module writes the token body as plain JSON and deliberately cannot
import the verifier, which lives in `garmd/internal/authn`. Nothing currently
fails if the two disagree — a renamed claim would be found by a developer
whose tokens stopped working, not by CI.

In the monorepo this was closed by a single test that minted with the IdP and
verified with the real verifier in one process. That test is split: the half
that checks the signature and the claims is here (`claimsOf`), and the half
that folds a chain into a `Principal` belongs with the verifier.

The intended fix is a cross-repository CI check rather than a shared module:
`garmd` clones this repository, mints against it, and asserts the `Principal`
it gets. That keeps the drift caught with no build edge in either direction —
the same shape as `garm`'s conformance cases. It is not built.

Until then the risk is bounded by the claim set being small and the tests on
both sides naming their expectations explicitly.

- `garm.kind` is refused here when it is misspelled, and that check exists
  only here. The verifier maps an unrecognised kind to no kind at all without
  saying so, so a second minter — or a hand-rolled curl against a different
  tool — still has the silent path this one closed.
- `tenant` is stamped from configuration and never validated against anything.
  Nothing here knows which tenants exist; a typo mints a token for a tenant
  that has no data, which reads as an empty result rather than an error.

## The UI's tool list needs a catalogue surface garmd does not serve

`/tools` mints for a persona and asks garm what that principal can see, which
is the clearest demonstration of folding there is — watch the list shrink when
you route through a lower-privileged agent.

It calls `garm.v1.ToolCatalogService/ListTools`, and `garmd` has no catalogue
service yet. The panel reports that it could not reach garm, which is honest
but not useful. It lights up when the surface lands; nothing here needs to
change.

## Only the IdP has been ported

`gen`, `lint`, `manifest`, the tool index and the agent scaffolding are still
in the private monorepo. They arrive as the planes they serve are ported.
