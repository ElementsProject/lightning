# crates.io Trusted Publishing migration

This patch replaces the long-lived Cargo registry token in
`.github/workflows/crate-io.yml` with GitHub OIDC + crates.io Trusted
Publishing. It is intentionally **not** active merely because workflow YAML
refers to the environment.

## Required maintainer preparation (must precede merge)

1. On crates.io, configure a Trusted Publisher for **each actually
   published crate** (and each workspace member that `katyo/publish-crates`
   may publish). Use owner `ElementsProject`, repository `lightning`,
   workflow filename `crate-io.yml`, and environment `release-cargo`.
   The registry-side configuration must agree with GitHub's OIDC claims.
2. Configure the repository's `release-cargo` GitHub environment with
   independent required reviewers, **prevent self-review**, and allowed
   deployment branch `master` only. The published crates must be owned by
   accounts authorized to register the Trusted Publisher configuration.
3. Require independent CODEOWNERS review for changes to this workflow,
   Cargo manifests and publishing scripts. Keep `master` protected from
   force-pushes and direct unreviewed updates.
4. In a **maintainer-controlled non-production validation**, verify that a
   branch dispatch is skipped, a canonical master dispatch waits for
   environment approval, and the OIDC token exchange identifies the expected
   workflow and environment. Never perform a test publish to actual
   production package names just to validate the setup. Consider a
   disposable test crate or staging registry for the token/publish journey.
5. After the Trusted Publisher configuration is tested and an approved
   release succeeds, **revoke and delete the former long-lived
   CARGO_REGISTRY_TOKEN** from repository/organization secrets and registry
   permissions; inspect whether any other workflows still depend on it.
6. Approve the required workflow change together with the separate release
   authority patch: the repository's release tag ruleset still needs a
   restricted tag-creation rule, and other release secrets must be scoped
   to protected environments. Publishing crates is one part of that system.

## Expected behavior

- Only `ElementsProject/lightning` at `refs/heads/master` can request
  the `release-cargo` environment.
- The auth action exchanges an OIDC identity for a short-lived token and
  automatically revokes that token in its post-job phase.
- The existing `katyo/publish-crates` action still controls dependency
  ordering and unchanged-version skipping for the four current paths:
  `cln-rpc`, `plugins`, `cln-grpc` and `lsps-types`.
- The token cannot be minted in a fork without the registry's trusted
  publisher configuration and matching repository identity.
- A production publish, maintainer environment approval, package
  ownership, and action compatibility cannot be proven by a syntax test.

## Source-only acceptance

Before merging, run `actionlint` on the changed workflow, review every
pinned action commit and trace each action's token input. Only the auth
step should request OIDC. Prefer a non-publishing/isolated test of the
workflow on the exact branch; do not expose an existing registry token.
