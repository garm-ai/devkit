# devkit

The garm development toolchain. One rule governs everything here.

## This module mints identities

A binary that can mint tokens can assert any identity — any clearance, any
compartment, any delegation chain. Two invariants follow, and neither is
negotiable:

1. **Nothing in a request path may depend on this module.** Not `garm`, not
   `garmd`, not a tool service. If something needs a token, it gets one over
   HTTP from a running `garmdev idp`, never by importing this.
2. **Nothing here may import the verifier, or the product at all.** The token
   body is plain JSON on purpose. This also keeps devkit building when the
   product does not, which is when the tools matter most.

The IdP binds loopback only and refuses anything else. Do not add a flag to
relax that, and do not add authentication to `/token` — it hands out
identities freely by design, which is safe only because nothing off this
machine can ask.

## Personas are a file

There is no create/update/delete endpoint and there should not be. A dev IdP
with a CRUD API starts to look like a product, and the next step is a staging
environment pointed at it. Management is editing the file, which keeps
personas reviewable, diffable and usable as test fixtures.

## Conventions

- Comments say WHY and what breaks otherwise, never what the line does.
- Test names are sentences about behaviour.
- `mise run ci` is what CI runs. Use `mise run test`, not bare `go test` — it
  carries `-race` and a timeout.
