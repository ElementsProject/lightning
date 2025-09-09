---
title: "Release Checklist"
slug: "release-checklist"
hidden: false
createdAt: "2023-12-07T10:00:00.000Z"
updatedAt: "2023-12-07T10:00:00.000Z"
---
# Release checklist

Here's a checklist for the release process.

## Leading Up To The Release

1. Talk to team about whether there are any changes which MUST go in this release which may cause delay.
2. Look through outstanding issues, to identify any problems that might be necessary to fixup before the release. Good candidates are reports of the project not building on different architectures or crashes.
3. Identify a good lead for each outstanding issue, and ask them about a fix timeline.
4. Create a milestone for the _next_ release on Github, and go though open issues and PRs and mark accordingly.
5. Ask (via email) the most significant contributor who has not already named a release to name the release (use
   `devtools/credit --verbose v<PREVIOUS-VERSION>` to find this contributor). CC previous namers and team.

## Preparing for -rc1

1. Check that `CHANGELOG.md` is well formatted, ordered in areas, covers all signficant changes, and sub-ordered approximately by user impact & coolness.
2. Use `devtools/changelog.py` to collect the changelog entries from pull request commit messages and merge them into the manually maintained `CHANGELOG.md`.  This does API queries to GitHub, which are severely
   ratelimited unless you use an API token: set the `GH_TOKEN` environment variable to a Personal Access Token from <https://github.com/settings/tokens>
3. Create a new CHANGELOG.md heading to `v<VERSION>rc1`, and create a link at the bottom. Note that you should exactly copy the date and name format from a previous release, as the `build-release.sh` script relies on this.
4. Update the package versions: `uv run make update-versions NEW_VERSION=v<VERSION>rc1`
5. Create a PR with the above.

## Releasing -rc1

1. Merge the above PR.
2. Tag it `git pull && git tag -s v<VERSION>rc1`. Note that you should get a prompt to give this tag a 'message'. Make sure you fill this in.
3. Confirm that the tag will show up for builds with `git describe`. We don't push it to GitHub yet, just in case the following steps fail, and more fixes are required!
4. Run `contrib/cl-repro.sh` to generate the required `cl-repro-<codename>` builder images for the reproducible build environment.
5. Execute `tools/build-release.sh bin-Ubuntu sign` to locally reproduce the release, generating a matching `SHA256SUMS-v<VERSION>` file and signing it with your GPG key.
6. Push the tag to trigger the "Release 🚀" CI action, which drafts a new `v<VERSION>rc1` pre-release on GitHub and uploads reproducible builds alongside the `SHA256SUMS-v<VERSION>` file and its signature from the `cln@blockstream.com` key.
7. Verify your local `SHA256SUMS-v<VERSION>` file matches the one in the draft release, then append your local signatures to the release's `SHA256SUMS-v<VERSION>.asc` file to attest to the build's integrity.
8. Announce rc1 release on core-lightning's release-chat channel on Discord & Telegram.
9. Use `devtools/credit --verbose v<PREVIOUS-VERSION>` to get commits, days and contributors data for release note.
10. Prepare release notes draft including information from above step, and share with the team for editing.
11. Upgrade your personal nodes to the rc1, to help testing.
12. Github action `Publish Python 🐍 distributions 📦 to PyPI and TestPyPI` uploads the pyln modules on test PyPI server. Make sure that the action has been triggered with RC tag and that the modules have been published on `https://test.pypi.org/project/pyln-*/#history`.
13. Docker image publishing is handled by the GitHub action `Build and push multi-platform docker images`. Ensure that this action is triggered and that the RC image has been successfully uploaded to Docker Hub after the action completes. Alternatively, you can publish Docker images by running the `tools/build-release.sh docker` script. The GitHub action takes approximately 3-4 hours, while the script takes about 6-7 hours. It is highly recommended to test your Docker setup if you haven't done so before. Prior to building docker images by `tools/build-release.sh` script, ensure that `multiarch/qemu-user-static` setup is working on your system as described [here](https://docs.corelightning.org/docs/docker-images#setting-up-multiarchqemu-user-static).

## Releasing -rc2, ..., -rcN

1. Update CHANGELOG.md by changing rc(N-1) to rcN. Update the changelog list with information from newly merged PRs also.
2. Update the package versions: `uv run make update-versions NEW_VERSION=v<VERSION>rcN`
3. Add a PR with the rcN.
4. Tag it `git pull && git tag -s v<VERSION>rcN && git push --tags`.
5. Pushing the tag automatically starts the "Release 🚀" CI job, creating a draft pre-release and uploading reproducible builds with their `SHA256SUMS` files signed by the project key.
6. Set up the reproducible build environment by running the script `contrib/cl-repro.sh` to generate the necessary builder images.
7. Use the command `tools/build-release.sh bin-Ubuntu sign` to locally rebuild the release and generate a personal signature file for the checksums.
8. After confirming the local and pre-release `SHA256SUMS-v<VERSION>` files match, append your signatures to the pre-release's `SHA256SUMS-v<VERSION>.asc` file to formally attest to the build's validity.
9. Announce tagged rc release on core-lightning's release-chat channel on Discord & Telegram.
10. Upgrade your personal nodes to the rcN.
11. Confirm that Github actions for PyPI and Docker publishing are working as expected.

## Tagging the Release

1. Update the CHANGELOG.md; remove -rcN in both places, update the date and add title and namer.
2. Update the contrib/pyln package versions: `uv run make update-versions NEW_VERSION=v<VERSION>`
3. Add a PR with that release.
4. Merge the PR, then:
   - `git pull`
   - `VERSION=23.05; git tag -a -s v$VERSION -m v$VERSION`
   - `git push --tags`
5. Pushing the tag will trigger the CI pipeline, which will draft the pre-release and upload the build artifacts with project-signed checksums.
6. Prepare the build environments by executing the `contrib/cl-repro.sh` script.
7. Run `tools/build-release.sh bin-Ubuntu sign` (with `--sudo` if you need root to run Docker) to:
   - Create reproducible zipfile
   - Build non-reproducible Fedora image
   - Build reproducible Ubuntu-v20.04, Ubuntu-v22.04 and Ubuntu-v24.04 images. Follow [link](https://docs.corelightning.org/docs/repro#building-using-the-builder-image) for manually Building Ubuntu Images.
   - Build Docker images for amd64 and arm64v8. Follow [link](https://docs.corelightning.org/docs/docker-images) for more details on Docker publishing.
   - Create and sign checksums. Follow [link](https://docs.corelightning.org/docs/repro#co-signing-the-release-manifest) for manually signing the release.
8. If you used `--sudo`, the tarballs may be owned by root, so revert ownership if necessary:
   `sudo chown ${USER}:${USER} *${VERSION}*`
9. Verify the checksums match the pre-release `SHA256SUMS-v<VERSION>`, then append your signatures to the official signature `SHA256SUMS-v<VERSION>.asc` file to confirm the build's integrity.
10. Send `SHA256SUMS-v<VERSION>` & `SHA256SUMS-v<VERSION>.asc` files to the rest of the team to check and sign the release.
11. Team members can verify the release with the help of `build-release.sh`:
   - Copy the release captain's `SHA256SUMS-v<VERSION>` and `SHA256SUMS-v<VERSION>.asc` into the root folder (`lightning`).
   - Run `tools/build-release.sh --verify`. It will create reproducible images, verify checksums and sign.
   - Send your signatures from `release/SHA256SUMS-v<VERSION>.asc` to release captain.
   - Or follow [link](https://docs.corelightning.org/docs/repro#verifying-a-reproducible-build) for manual verification instructions.
12. Append signatures shared by the team into the `SHA256SUMS-v<VERSION>.asc` file, verify with `gpg --verify SHA256SUMS-v<VERSION>.asc` and include the file in the draft release.
13. The GitHub action `Publish Python 🐍 distributions 📦 to PyPI and TestPyPI` should upload the pyln modules to pypi.org. However, this can also be done manually by running `uv run make pyln-release`. This process requires keys for each of the `pyln-client`, `pyln-proto`, and `pyln-testing` modules to be accessible to uv. You can set the key as an environment variable and build and publish each pyln release independently:
    - `export UV_PUBLISH_TOKEN=<pyln-client token>`
    - `uv run make pyln-release-client`
    - ... repeat for each pyln package with the appropriate token.
14. Publish multi-arch Docker images (`elementsproject/lightningd:v${VERSION}` and `elementsproject/lightningd:latest`) to Docker Hub either using the GitHub action `Build and push multi-platform docker images` or by running the `tools/build-release.sh docker` script. Prior to building docker images by `tools/build-release.sh` script, ensure that `multiarch/qemu-user-static` setup is working on your system as described [here](https://docs.corelightning.org/docs/docker-images#setting-up-multiarchqemu-user-static).


## Performing the Release

1. Edit the GitHub draft and include the `SHA256SUMS-v<VERSION>.asc` file.
2. Publish the release as not a draft.
3. Announce the final release on core-lightning's release-chat channel on Discord & Telegram.
4. Send a mail to c-lightning and lightning-dev mailing lists, using the same wording as the Release Notes in GitHub.
5. Write release blog, post it on [Blockstream](https://blog.blockstream.com/) and announce the release on Twitter.

## Post-release

1. Create a PR to update Makefile's CLN_NEXT_VERSION and important dates for the next release on `.github/PULL_REQUEST_TEMPLATE.md`.
2. Look through PRs which were delayed for release and merge them.
3. Close out the Milestone for the now-shipped release.
4. Update this file with any missing or changed instructions.

## Performing the Point (hotfix) Release

1. Create a new branch named `release-<VERSION>.<POINT_VERSION>`, where each new branch is based on the commit from the previous release tag. For example, `release-<VERSION>.1` is based on `release-<VERSION>`, `release-<VERSION>.2` is based on `release-<VERSION>.1`, and so on.
2. Cherry-pick all necessary commits for the hotfix into the new branch.
3. Add entries for changes and fixed issues in `CHANGELOG.md` under a new heading for `v<VERSION>.<POINT_VERSION>`.
4. Update the python package versions by running `uv run make update-versions NEW_VERSION=<VERSION>.<POINT_VERSION>`
5. Create a new commit that includes the updates from `update-versions` and `CHANGELOG.md`.
6. Tag the release with `git pull && git tag -s v<VERSION>.<POINT_VERSION>`. You will be prompted to enter a tag message, ensure this is filled out.
7. Confirm that the tag is properly set up for builds by running `git describe`.
8. Trigger the pre-release by pushing the version tag with `git push --tags`; the CI will handle drafting the release and uploading the initial signed checksums.
9. Generate the required builder images by running `contrib/cl-repro.sh`.
10. Sign the release locally by running `tools/build-release.sh bin-Ubuntu sign` which will sign the release contents and create `SHA256SUMS-v<VERSION>` and `SHA256SUMS-v<VERSION>.asc` in the release folder.
11. Validate that your local checksums `SHA256SUMS-v<VERSION>` match the Draft release's, then add your signatures to the draft release's signature `SHA256SUMS-v<VERSION>.asc` file.
12. Share the `SHA256SUMS-v<VERSION>` and `SHA256SUMS-v<VERSION>.asc` files with the team for verification and signing.
13. Append the signatures received from the team to the `SHA256SUMS-v<VERSION>.asc` file. Verify the file using `gpg --verify SHA256SUMS-v<VERSION>.asc`. Then re-upload the file.
14. Finalize and publish the release (change it from draft to public).
15. Ensure that the GitHub Actions for `Publish Python 🐍 distributions 📦 to PyPI and TestPyPI` and `Build and push multi-platform docker images` are functioning correctly. Check that the `PyPI` modules published on `https://pypi.org/project/pyln-*` and that the Docker image has been uploaded to Docker Hub.
16. Announce the hotfix release in the core-lightning release-chat channel on Discord and on Telegram.
