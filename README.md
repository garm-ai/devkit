# devkit

The garm development toolchain: things you run on a laptop or in CI, never in
a request path.

Today that is one command — a local identity provider, so a local `garmd` can
verify real signatures with no IdP in the picture.

```
go install github.com/garm-ai/devkit/cmd/garmdev@latest

garmdev idp --personas examples/personas.yaml
curl -s '127.0.0.1:7450/token?user=alice'
curl -s '127.0.0.1:7450/token?user=bob&as=triage-bot'   # delegated
```

Point `garmd` at `http://127.0.0.1:7450/.well-known/jwks.json` and it will
verify those tokens the same way it verifies your bank's.

### Tokens name a tenant

Every persona token carries a `tenant` claim: the persona's own, else
`--tenant`, else the `tenant:` at the top of the personas file —
`examples/personas.yaml` declares `bank`, so the quickstart above mints it.

It is not decoration. Confinement to a tenant's own data depends on the value
flowing from a verified token, so the STS refuses to exchange a token whose
`tenant` is empty — and a dev IdP that omitted it would make every exchange
fail with an `access_denied` that says nothing about tenants. The ad-hoc form
takes `?tenant=` as it always has.

## Why this is its own repository

It mints tokens. A binary that can mint tokens can assert any identity — any
clearance, any compartment, any delegation chain — and "dev mode" is exactly
the kind of switch that ends up on in a hurry somewhere it should not be.

So it is not in `garm`. `garm` is the CLI that lands on every developer
machine and every enterprise build host, and a token minter inside it is a
token minter everywhere. Here, minting requires deliberately fetching a module
whose name says what it is, and the `require` line is the audit trail.

Two consequences follow, and both are enforced rather than documented:

- **Nothing in a request path may depend on this module.** `garm` and `garmd`
  assert that in CI. Crossing the line means adding
  `require github.com/garm-ai/devkit`, which is one grep and visible in review.
- **This module may not import the verifier.** The token body is written as
  plain JSON; nothing here knows the types that will read it. That also keeps
  devkit building when the product does not, which is when you most need the
  tools.

The IdP refuses to bind anything but loopback, for the same reason. There is
no authentication on `/token` and there should not be — the whole point is
that it hands out identities freely, which is only safe when nothing else can
ask.

## Personas

Roles, users, agents and who may act for whom, in a YAML file — see
[`examples/personas.yaml`](examples/personas.yaml), which is loaded by the
test suite so it cannot rot.

Three things about that file are load-bearing rather than incidental:

**garm never sees a role.** A role is a bundle of claims, and bundling is an
identity provider's job. The token carries the clearance, compartments and
verbs a role expands to. A role reaching the policy chain would be a second
vocabulary for answering a question the chain already answers.

**Roles union; delegation intersects.** Holding two roles gives you more.
Acting on behalf of someone gives you less. Same token, opposite operations —
conflating them would either strip authority from multi-role users or let
delegation widen it.

**`may_act_for` is enforced when minting, and garm never sees it.** garm folds
a chain it is given and can only narrow it, but it cannot know whether the
delegation was permitted. The IdP asserts that by agreeing to sign. Try
`?user=alice&as=triage-bot` — `triage-bot` may act for `bob` only, and minting
the chain anyway would teach that delegation is unconstrained.

It is a file and not a store because everything in it is configuration a pull
request can argue about. A dev IdP with a CRUD API starts to look like a
product, and the next step after that is a staging environment pointed at it.

## Development

```
mise install
mise run ci      # exactly what CI runs
mise run idp     # the IdP with the example personas
```
