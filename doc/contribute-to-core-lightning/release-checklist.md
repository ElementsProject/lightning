---
title: Release Checklist
slug: release-checklist
privacy:
  view: public
---
# Release checklist

Here's a checklist for the release process.

## Leading Up To The Release

1. Talk to team about whether there are any changes which MUST go in this release which may cause delay.
2. Look through outstanding issues, to identify any problems that might be necessary to fixup before the release. Good candidates are reports of the project not building on different architectures or crashes.
3. Identify a good lead for each outstanding issue, and ask them about a fix timeline.
4. Create a milestone for the _next_ release on Github, and go though open issues and PRs and mark accordingly.
5. Ask (via email) the most significant contributor who has not already named a release to name the release (use `devtools/credit --verbose v<PREVIOUS-VERSION>` to find this contributor). CC previous namers and team.

## Preparing for -rc1

1. Make sure any `CHANGELOG.md` changes from point releases have been imported.
2. Use `devtools/changelog.py` to collect the changelog entries from pull request commit messages and merge them into the manually maintained `CHANGELOG.md`. This does API queries to GitHub, which are severely ratelimited unless you use an API token: set the `GH_TOKEN` environment variable to a Personal Access Token from https://github.com/settings/tokens
3. Check that `CHANGELOG.md` is well formatted, ordered in areas, covers all significant changes, and sub-ordered approximately by user impact & coolness.
4. Manually remove any entries which were mentioned for in the previous point releases (they will be duplicates!)
5. Create a new CHANGELOG.md heading to `v<VERSION>rc1`, and create a link at the bottom. Note that you should exactly copy the date and name format from a previous release, as the release tooling parses the date from it.
6. Update the package versions: `uv run make update-versions NEW_VERSION=v<VERSION>rc1`
7. Create a PR with the above.

## Releasing -rc1

1. Merge the above PR.
2. Tag it `git pull && git tag -s v<VERSION>rc1`. Note that you should get a prompt to give this tag a 'message'. Make sure you fill this in.
3. Confirm that the tag will show up for builds with `git describe`. We don't push it to GitHub yet, just in case the following steps fail, and more fixes are required!
4. Build and sign the release locally: `tools/reprobuild all`. This is the whole
   build — three static tarballs, the source zip, the multi-arch image and both
   signed manifests — and it needs only docker, coreutils and python3. Every rc is a
   rehearsal of the release flow, so do not skip it. The signing key has to answer
   before the build starts, so that an hour of building cannot end on a key nobody
   can reach. If you would rather not sit next to the machine for that hour, add
   `--wait-for-key`: the build then runs unattended and waits (30 minutes by
   default, `--wait-for-key=SECONDS` to change it) once it has something to sign,
   so you only need to plug in and unlock the smartcard at the end. It polls the
   key rather than waiting for a keypress, so this works for a detached run whose
   log you are tailing.
5. Publish the rc: `tools/reprobuild publish`. That is the whole publication —
   tarballs, manifests, signatures and the source zip to the download host, the
   multi-arch image to Docker Hub, the tag to GitHub, and the GitHub release.
   `latest` is never applied to an rc. **The "Release 🚀" workflow must be
   disabled** (`gh workflow disable "Release 🚀"`): pushing a tag would publish
   the pyln modules on its own schedule, and `publish` refuses while it is
   enabled. Re-enable it afterwards.
8. Announce rc1 release on core-lightning's release-chat channel on Discord & Telegram.
9. Use `devtools/credit --markdown v<PREVIOUS-VERSION>` to generate a single contributor list for the release notes. Use `devtools/credit --verbose v<PREVIOUS-VERSION>` for namer selection and detailed annotations.
10. Prepare release notes draft including the contributor list from above, and share with the team for editing.
11. Upgrade your personal nodes to the rc1, to help testing.
12. Github action `Publish Python 🐍 distributions 📦 to PyPI and TestPyPI` uploads the pyln modules on test PyPI server. Make sure that the action has been triggered with RC tag and that the modules have been published on `https://test.pypi.org/project/pyln-*/#history`.
13. The rc's Docker images were published in step 5 by `tools/reprobuild
    publish`, which pushes one multi-arch image built from the same tarballs
    that were signed. There is nothing to trigger in CI.

## Releasing -rc2, ..., -rcN

1. Update CHANGELOG.md by changing rc(N-1) to rcN. Update the changelog list with information from newly merged PRs also.
2. Update the package versions: `uv run make update-versions NEW_VERSION=v<VERSION>rcN`
3. Add a PR with the rcN, and merge it.
4. Tag it `git pull && git tag -s v<VERSION>rcN && git push origin v<VERSION>rcN`.
5. Build, sign and publish as for rc1: `tools/reprobuild all`, then
   `tools/reprobuild publish`.
6. Co-signers rebuild with `tools/reprobuild verify SHA256SUMS-v<VERSION>rcN` and
   send you their signatures; append them to the manifest's `.asc`.
9. Announce tagged rc release on core-lightning's release-chat channel on Discord & Telegram.
10. Upgrade your personal nodes to the rcN.
11. Confirm the PyPI action worked as expected. Docker images are published by
    `tools/reprobuild publish`, not by CI.

## Tagging the Release

1. Update CHANGELOG.md: remove -rcN in both places, update the date, and add the title and namer.
2. Update project-wide package versions: `uv run make update-versions NEW_VERSION=v<VERSION>`
3. Create a PR with above changes.
4. After the PR is merged, create and push the release tag:
   - Run `git pull`.
   - Set the current release version in your shell (e.g., if the current release is `v26.04`): `VERSION=26.04`
   - Create a signed, annotated tag: `git tag -a -s v$VERSION -m "v$VERSION"`
   - Push the tag: `git push origin v$VERSION`
5. Do **not** push the tag by hand: `tools/reprobuild publish` pushes it, last,
   once everything else has gone out and been verified. Confirm the
   "Release 🚀" workflow is disabled.
6. Build and sign everything: `tools/reprobuild all`. It ends with
   `SHA256SUMS-v<VERSION>` and `SHA256SUMS-v<VERSION>-armhf`, each signed with
   your key. The build takes 1–2 hours for all three rows.
7. Send both manifests and their signatures to the co-signers. They run
   `tools/reprobuild verify SHA256SUMS-v<VERSION>` — which rebuilds from the
   commit and timestamp the manifest names — and send back
   `SHA256SUMS-v<VERSION>.asc.<keyid>`.
8. Append their signatures to `SHA256SUMS-v<VERSION>.asc` and check the result
   with `gpg --verify SHA256SUMS-v<VERSION>.asc SHA256SUMS-v<VERSION>` — always
   pass the manifest as the second argument, or `gpg` may verify a payload
   embedded in the `.asc` and exit successfully without reading the checksums. **Three good
   signatures** — yours plus two co-signers', distinct keys from
   `contrib/keys/` — are required before publishing; `publish` checks. The
   `armhf` manifest may carry only your signature, which does not hold up the
   release (see the caveat in the [reproducible builds
   page](https://docs.corelightning.org/docs/repro)).
9. Publish: `tools/reprobuild publish`, or `tools/reprobuild publish --latest`
   if this release should also become `latest` on Docker Hub. This uploads the
   artifacts and the source zip, reads them back and checks them against the
   signed manifest, pushes the images, pushes the tag and creates the GitHub
   release — in that order, so the irreversible step comes last.
10. Run the acceptance suite if you have not since certifying:
    `tools/reprobuild accept`. It runs the portability matrix and the two-tree
    probe; `tools/reprobuild certify` is the fuller version that rebuilds
    everything from source without the binary cache.
13. The GitHub action `Publish Python 🐍 distributions 📦 to PyPI and TestPyPI` should upload the pyln modules to pypi.org. However, this can also be done manually by running `uv run make pyln-release`. This process requires keys for each of the `pyln-client`, `pyln-proto`, and `pyln-testing` modules to be accessible to uv. You can set the key as an environment variable and build and publish each pyln release independently:
    - `export UV_PUBLISH_TOKEN=<pyln-client token>`
    - `uv run make pyln-release-client`
    - ... repeat for each pyln package with the appropriate token.
14. Docker images were published by `tools/reprobuild publish` in step 9; there
    is nothing to trigger in CI, and the CI image workflow stays disabled.
    Re-enable the "Release 🚀" workflow if the project wants it back on
    (`gh workflow enable "Release 🚀"`).

## Performing the Release

1. `tools/reprobuild publish` in the previous section already pushed the tag and
   created the GitHub release **as a draft** — the artifacts and the tag are
   public at that point, but the release page is not. Check that it reads the way
   you want, publish it, and re-enable the "Release 🚀" workflow
   (`gh workflow enable "Release 🚀"`) if the project wants it back on.
2. Announce the final release on core-lightning's release-chat channel on Discord & Telegram.
3. Send a mail to c-lightning mailing list (`c-lightning@lists.ozlabs.org`), using the same wording as the Release Notes in GitHub.
4. Write release blog, post it on [Blockstream](https://blog.blockstream.com/) and announce the release on Twitter.

## Post-release

1. Create a PR to update:
  * `Makefile`: variables CLN_NEXT_VERSION and CLN_PREV_VERSION (this may break tests as deprecated things are disabled!)
  * `tools/lightning-downgrade.c`: to downgrade to the just-released version.
  * `.github/workflows/ci.yaml`: change old-cln to download the just-released version.
  * `.github/PULL_REQUEST_TEMPLATE.md` for important dates for the next release.
2. Look through PRs which were delayed for release and merge them.
3. Close out the Milestone for the now-shipped release.
4. Update this file with any missing or changed instructions.
5. Fetch the latest bolt revision in ../bolts.  Then run `./devtools/bolt-catchup.sh` to update BOLTVERSION in the Makefile and run `make check-bolt-quotes`.  It may get confused by merges in the BOLTs repository, so you may have to do some manual work.  Note: this step may involve a significant amount of work for new spec changes!
6. Go through `doc/developers-guide/deprecated-features.md` and remove features and code whose `Last Supported` was the prior version (i.e. now two versions ago: we give one version where the user can use `i-promise-to-fix-broken-api-user=FEATURENAME` to re-enable it).  Also remove the features from any schemas and other documentation.

## Performing the Point (hotfix) Release

1. Create a new branch named `release-<VERSION>.<POINT_VERSION>`, where each new branch is based on the commit from the previous release tag. For example, `release-<VERSION>.1` is based on `release-<VERSION>`, `release-<VERSION>.2` is based on `release-<VERSION>.1`, and so on.
2. Cherry-pick all necessary commits for the hotfix into the new branch.
3. Add entries for changes and fixed issues in `CHANGELOG.md` under a new heading for `v<VERSION>.<POINT_VERSION>`.
4. Update project package versions by running `uv run make update-versions NEW_VERSION=<VERSION>.<POINT_VERSION>`
5. Create a new commit that includes the updates from `update-versions` and `CHANGELOG.md`.
6. Tag the release with `git pull && git tag -s v<VERSION>.<POINT_VERSION>`. You will be prompted to enter a tag message, ensure this is filled out.
7. Confirm that the tag is properly set up for builds by running `git describe`.
8. Do not push the tag by hand; `tools/reprobuild publish` does it. Confirm the
   "Release 🚀" workflow is disabled.
9. Build and sign: `tools/reprobuild all`.
10. Send both manifests and their signatures to the co-signers, who run
    `tools/reprobuild verify SHA256SUMS-v<VERSION>.<POINT_VERSION>` and send
    back their detached signatures.
11. Append their signatures; three good ones from distinct committed keys are
    required before publishing. Check the result with `gpg --verify
    SHA256SUMS-v<VERSION>.<POINT_VERSION>.asc
    SHA256SUMS-v<VERSION>.<POINT_VERSION>` — the manifest must be the second
    argument, or `gpg` may verify a payload embedded in the `.asc` instead.
12. `tools/reprobuild publish`. Add `--latest` only if this point release should
    become `latest` on Docker Hub. It publishes the artifacts, pushes the tag and
    creates the GitHub release.
14. Finalize and publish the release (change it from draft to public).
15. Check that the `Publish Python 🐍 distributions 📦 to PyPI and TestPyPI`
    action published the pyln modules on `https://pypi.org/project/pyln-*`, or
    publish them manually with `uv run make pyln-release`. Docker images were
    already pushed in step 12.
16. Create a PR to merge updates from `update-versions` and `CHANGELOG.md` into `master` to keep it up-to-date for the next release.
17. Announce the hotfix release in the core-lightning release-chat channel on Discord and on Telegram.
