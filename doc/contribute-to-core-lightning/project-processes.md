---
title: Project Processes
slug: project-processes
content:
  excerpt: How we triage issues, review and merge PRs, and cut releases — and why.
privacy:
  view: public
---
This document describes how the Core Lightning project handles issues, pull requests, reviews and releases, and — just as importantly — *why* we handle them that way. It is the authoritative reference we point to when explaining a triage action: why an issue was closed, why a PR is still marked as Draft, or why a reviewer has not looked at a branch yet. If a maintainer's action surprises you, this document should explain the reasoning behind it; if it doesn't, that is a bug in this document and worth an issue of its own.

None of these processes are meant as judgments. Closing an issue, or asking for a PR to be reworked, is bookkeeping that keeps the project manageable — not a statement about the value of the report or the contribution.

## Issue Lifecycle

The issue tracker is our shared to-do list: it should contain actionable items — bugs we intend to fix and features we intend to build. Everything we do in triage serves that goal, because a tracker full of unactionable or stale entries hides the issues that genuinely need attention.

### Triage labels

Issues are classified along three orthogonal dimensions, plus free-form area labels:

- `Type::*` — what kind of item this is: `Type::Bug` for defects, `feature` for enhancements, `Type::Repro` for reproductions of existing issues (see [Reproduction PRs](#reproduction-prs) below).
- `Status::*` — where the item is in its lifecycle: `Status::Needs Info`, `Status::Backlog`, `Status::Assigned`, `Status::Blocked`, `Status::Deferred`, `Status::Duplicate`, `Status::Ready for Review`.
- `Severity::*` — impact assessment for bugs, from `Severity::Critical` (crashes, data or fund loss, no workaround) down to `Severity::Low` (cosmetic).

In addition, area labels (`gossip`, `hsmd`, `pay-plugin`, …) route issues to the developers most familiar with that part of the codebase.

### Why we close issues

We close issues for one of the following reasons, and the closing comment should always say which one applies:

- **Missing information**: If we cannot reproduce or diagnose an issue without more details, we ask for them and apply `Status::Needs Info`. If the reporter does not respond within roughly 30 days, we close the issue manually. This is purely housekeeping: an issue we cannot act on only obscures the ones we can. **Reopening is always welcome** — if the missing information turns up later, comment on the issue and we will reopen it.
- **Support questions**: The tracker is for defects and feature work, not for help with running a node. Questions are redirected to the community channels (Discord and Telegram), where far more people can help, and the issue is closed. This keeps the tracker actionable and gets the asker a faster answer.
- **Duplicates**: Closed with `Status::Duplicate` and a pointer to the canonical issue, so that discussion and subscriptions concentrate in one place.
- **Out of scope / won't fix**: If a request does not fit the project's direction, we close it with an explanation rather than letting it linger with no intention of acting on it. An open issue is an implicit promise; we prefer to be honest when we do not intend to keep it.
- **Fixed**: Issues are closed when the fixing PR is merged into `master`, not when the fix ships in a release. The CHANGELOG and release notes track which release contains which fix; if you are affected, the fix will be in the next release, or you can build `master` directly.

## Pull Requests

### Rebase, not merge

Core Lightning uses a rebase workflow: PRs are rebased on top of the destination branch rather than integrated via merge commits. This keeps history linear, which makes `git bisect` effective and the project history readable.

The rebase model puts corresponding expectations on the commits themselves:

- **Commits are atomic and bisectable**: each commit should build and pass tests on its own, representing one logical change. Since every commit in a PR lands on `master` as-is, a broken intermediate commit breaks bisection for everyone.
- **Changelog entries live in commit messages**: user-visible changes carry a `Changelog-*` footer in the relevant commit, as described in the [coding style guidelines](https://docs.corelightning.org/docs/coding-style-guidelines#changelog-entries-in-commit-messages). These are collected automatically by `devtools/changelog.py` at release time, so the CHANGELOG writes itself from well-written commits.

During review, how you incorporate feedback is up to you: force-pushing rewritten commits and appending fixup commits are both fine. What matters is the final state of the branch at merge time — a clean series of atomic commits.

### Draft status

We keep PRs marked as **Draft until they are ready for review**, and reviewers will wait for a PR to be undrafted before reviewing it, unless the author explicitly asks for early feedback.

This convention serves two purposes:

- It gives authors a **safe space to experiment**: you can open a PR early to run CI, share a link, or think out loud, without triggering review of half-finished work.
- It **keeps the review workload at acceptable levels**: reviewer time is the scarcest resource in the project, and spending it on code that is still changing wastes it.

Undrafting a PR is therefore a meaningful signal: it says "this is finished from my side, please review". Conversely, if your drafted PR is not getting reviews, that is the convention working as intended — undraft it, or ping a reviewer if you want feedback on a work in progress.

### Reproduction PRs

Sometimes a PR exists only to reproduce or demonstrate an issue — typically a failing test case. These are valuable: a reliable reproduction is often the hardest part of a fix. But they can never be merged as they are, since they would land a failing test on `master`, and CI would then reject every PR built on top.

We therefore label such PRs `Type::Repro` and keep them as Drafts. The label and Draft status tell reviewers and maintainers: do not review or merge this; it is a starting point for whoever picks up the underlying issue.

A developer taking up the issue has two options:

- **Registered contributors and maintainers** can take over the repro branch directly, add the fix, and undraft the PR once the issue is addressed — undrafting signals readiness for review as usual.
- **Everyone else** can create their own branch and PR that includes the original repro commits (preserving their authorship) followed by the fix. The original repro PR is then closed as superseded, with a pointer to the new PR.

### Review and merging

Reviewers are assigned by maintainers as part of triage, matching PRs to developers familiar with the affected area; authors are also welcome to ask specific people for review.

To be merged, a PR needs:

- **one ACK from a maintainer** (an approving review), and
- **green CI** on the final state of the branch.

Any maintainer may then perform the merge. Larger or riskier changes will naturally attract more scrutiny before a maintainer is comfortable ACKing them — the single-ACK rule is a floor, not a cap on diligence.

## Releases

Core Lightning releases **once per quarter**, and releases are numbered after the month they are cut: release `XX.YY` was cut in year 20XX, month YY (e.g. `25.09` for September 2025).

### The release branching model

A release is prepared as follows:

1. The `CHANGELOG.md` is finalized and all version numbers are updated **in a commit on `master`**.
2. A release branch named `release-XX.YY` is created at that version-bump commit.
3. The entire release process — release candidates, the final release, and any subsequent hotfix (point) releases — happens **on the release branch**.

This model has two deliberate properties:

- **Development never stops.** Merging into `master` continues while the release is being stabilized; the release candidate cycle and any hotfixes are fully isolated on the release branch, so a problem found during the RC phase never blocks unrelated development.
- **No backporting of release metadata.** Because the version bump and CHANGELOG updates are committed on `master` *before* branching, `master` is always up to date, and we never have to cherry-pick version or changelog commits back from the release branch.

Changes that need to land in the release after branching — fixes found during the RC cycle, or hotfixes after the release — are **cherry-picked from `master` onto the release branch**, together with their version-number and CHANGELOG updates. Fixes are merged to `master` first, then cherry-picked; this guarantees that nothing shipped in a release can be missing from `master`.

The mechanical, step-by-step procedure (tagging, reproducible builds, signing, publishing) is documented in the [release checklist](https://docs.corelightning.org/docs/release-checklist).

## Security Issues

Vulnerabilities are deliberately **not** handled through the public issue tracker or public PRs: reporting, embargo and disclosure follow the [security policy](https://docs.corelightning.org/docs/security-policy). If you believe you have found a security-relevant bug, please follow that process instead of opening an issue.
