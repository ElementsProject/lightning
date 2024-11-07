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
4. Update the package versions: `make update-versions NEW_VERSION=<VERSION>`
5. Create a PR with the above.

## Releasing -rc1

1. Merge the above PR.
2. Tag it `git pull && git tag -s v<VERSION>rc1`. Note that you should get a prompt to give this tag a 'message'. Make sure you fill this in.
3. Confirm that the tag will show up for builds with `git describe`
4. Push the tag to remote `git push --tags`.
5. Pushing the tag will kickoff the "Release 🚀" CI action which builds the release targets. Verify this action completed successfully and download the artifact it produces named `c-lightning-<release tag>`.zip and extract it into a directory named `release` in the root of your local repository. Ex. `unzip -d release/ ~/Downloads/c-lightning-<release tab>.zip`
6. Sign the release locally by running `tools/build-release.sh --without-zip sign` which will sign the release contents and create SHA256SUMS and SHA256SUMS.asc in the release folder.
7. Draft a new `v<VERSION>rc1` release on Github and check `Set as a pre-release` option.
8. Upload reproducible builds, SHA256SUMS and SHA256SUMS.asc from the release folder to newly drafted release.
9. Announce rc1 release on core-lightning's release-chat channel on Discord & [BuildOnL2](https://community.corelightning.org/c/general-questions/).
10. Use `devtools/credit --verbose v<PREVIOUS-VERSION>` to get commits, days and contributors data for release note.
11. Prepare release notes draft including information from above step, and share with the team for editing.
12. Upgrade your personal nodes to the rc1, to help testing.
13. Github action `Publish Python 🐍 distributions 📦 to PyPI and TestPyPI` uploads the pyln modules on test PyPI server. Make sure that the action has been triggered with RC tag and that the modules have been published on `https://test.pypi.org/project/pyln-*/#history`.
14. Docker image publishing is handled by the GitHub action `Build and push multi-platform docker images`. Ensure that this action is triggered and that the RC image has been successfully uploaded to Docker Hub after the action completes. Alternatively, you can publish Docker images by running the `tools/build-release.sh docker` script. The GitHub action takes approximately 3-4 hours, while the script takes about 6-7 hours. It is highly recommended to test your Docker setup if you haven't done so before. Prior to building docker images by `tools/build-release.sh` script, ensure that `multiarch/qemu-user-static` setup is working on your system as described [here](https://docs.corelightning.org/docs/docker-images#setting-up-multiarchqemu-user-static).

## Releasing -rc2, ..., -rcN

1. Update CHANGELOG.md by changing rc(N-1) to rcN. Update the changelog list with information from newly merged PRs also.
2. Update the package versions: `make update-versions NEW_VERSION=<VERSION>`
3. Add a PR with the rcN.
4. Tag it `git pull && git tag -s v<VERSION>rcN && git push --tags`
5. Draft a new `v<VERSION>rcN` pre-release on Github, upload reproducible builds, SHA256SUMS and SHA256SUMS.asc.
5. Announce tagged rc release on core-lightning's release-chat channel on Discord & [BuildOnL2](https://community.corelightning.org/c/general-questions/).
6. Upgrade your personal nodes to the rcN.
7. Confirm that Github actions for PyPI and Docker publishing are working as expected.

## Tagging the Release

1. Update the CHANGELOG.md; remove -rcN in both places, update the date and add title and namer.
2. Update the contrib/pyln package versions: `make update-pyln-versions NEW_VERSION=<VERSION>`
3. Add a PR with that release.
4. Merge the PR, then:
   - `export VERSION=23.05`
   - `git pull`
   - `git tag -a -s v${VERSION} -m v${VERSION}`
   - `git push --tags`
5. Run `tools/build-release.sh` to:
   - Create reproducible zipfile
   - Build non-reproducible Fedora image
   - Build reproducible Ubuntu-v18.04, Ubuntu-v20.04, Ubuntu-v22.04 images. Follow [link](https://docs.corelightning.org/docs/repro#building-using-the-builder-image) for manually Building Ubuntu Images.
   - Build Docker images for amd64 and arm64v8. Follow [link](https://docs.corelightning.org/docs/docker-images) for more details on Docker publishing.
   - Create and sign checksums. Follow [link](https://docs.corelightning.org/docs/repro#co-signing-the-release-manifest) for manually signing the release.
6. The tarballs may be owned by root, so revert ownership if necessary:
   `sudo chown ${USER}:${USER} *${VERSION}*`
7. Upload the resulting files to github and save as a draft.
   (<https://github.com/ElementsProject/lightning/releases/>)
8. Send `SHA256SUMS` & `SHA256SUMS.asc` files to the rest of the team to check and sign the release.
9. Team members can verify the release with the help of `build-release.sh`:
   1. Rename release captain's `SHA256SUMS` to `SHA256SUMS-v${VERSION}` and `SHA256SUMS.asc` to `SHA256SUMS-v${VERSION}.asc`.
   2. Copy them in the root folder (`lightning`).
   3. Run `tools/build-release.sh --verify`. It will create reproducible images, verify checksums and sign.
   4. Send your signatures from `release/SHA256SUMS.new` to release captain.
   5. Or follow [link](https://docs.corelightning.org/docs/repro#verifying-a-reproducible-build) for manual verification instructions.
10. Append signatures shared by the team into the `SHA256SUMS.asc` file, verify with `gpg --verify SHA256SUMS.asc` and include the file in the draft release.
11. The GitHub action `Publish Python 🐍 distributions 📦 to PyPI and TestPyPI` should upload the pyln modules to pypi.org. However, this can also be done manually by running `make pyln-release`. This process requires keys for each of the `pyln-client`, `pyln-proto`, and `pyln-testing` modules to be accessible to Poetry. You can configure the Python keyring library with a suitable backend to handle this, or alternatively, set the key as an environment variable and build and publish each pyln release independently:
    - `export POETRY_PYPI_TOKEN_PYPI=<pyln-client token>`
    - `make pyln-release-client`
    - ... repeat for each pyln package.
12. Publish multi-arch Docker images (`elementsproject/lightningd:v${VERSION}` and `elementsproject/lightningd:latest`) to Docker Hub either using the GitHub action `Build and push multi-platform docker images` or by running the `tools/build-release.sh docker` script. Prior to building docker images by `tools/build-release.sh` script, ensure that `multiarch/qemu-user-static` setup is working on your system as described [here](https://docs.corelightning.org/docs/docker-images#setting-up-multiarchqemu-user-static).


## Performing the Release

1. Edit the GitHub draft and include the `SHA256SUMS.asc` file.
2. Publish the release as not a draft.
3. Announce the final release on core-lightning's release-chat channel on Discord & [BuildOnL2](https://community.corelightning.org/c/general-questions/).
4. Send a mail to c-lightning and lightning-dev mailing lists, using the same wording as the Release Notes in GitHub.
5. Write release blog, post it on [Blockstream](https://blog.blockstream.com/) and announce the release on Twitter.

## Post-release

1. Wait for a week to see if we need any point releases!
2. Create a PR to update Makefile's CLN_NEXT_VERSION and important dates for the next release on `.github/PULL_REQUEST_TEMPLATE.md`.
3. Look through PRs which were delayed for release and merge them.
4. Close out the Milestone for the now-shipped release.
5. Update this file with any missing or changed instructions.

## Performing the Point (hotfix) Release

1. Create a new branch named `release-<VERSION>.<POINT_VERSION>`, where each new branch is based on the commit from the previous release tag. For example, `release-<VERSION>.1` is based on `release-<VERSION>`, `release-<VERSION>.2` is based on `release-<VERSION>.1`, and so on.
2. Cherry-pick all necessary commits for the hotfix into the new branch.
3. Add entries for changes and fixed issues in `CHANGELOG.md` under a new heading for `v<VERSION>.<POINT_VERSION>`.
4. Update the python package versions by running `make update-py-versions NEW_VERSION=<VERSION>.<POINT_VERSION>`
5. Create a new commit that includes the updates from `update-py-versions` and `CHANGELOG.md`.
6. Tag the release with `git pull && git tag -s v<VERSION>.<POINT_VERSION>`. You will be prompted to enter a tag message, ensure this is filled out.
7. Confirm that the tag is properly set up for builds by running `git describe`.
8. Push the tag to the remote repository `git push --tags`.
9. Create a new release draft for `v<VERSION>.<POINT_VERSION>` on GitHub, ensuring to check the `Set as a pre-release` option.
10. Follow the [reproducible build](https://docs.corelightning.org/docs/repro) instructions for [Builder image setup](https://docs.corelightning.org/docs/repro#builder-image-setup) to create builder images named `cl-repro-<codename>` required for the next step.
11. Run the following script to prepare the required builds `tools/build-release.sh bin-Fedora-28-amd64 bin-Ubuntu sign`.
12. Upload the reproducible builds along with `SHA256SUMS` and `SHA256SUMS.asc` files from the release folder to the newly drafted release.
13. Share the `SHA256SUMS` and `SHA256SUMS.asc` files with the team for verification and signing.
14. Append the signatures received from the team to the `SHA256SUMS.asc` file. Verify the file using `gpg --verify SHA256SUMS.asc`. Then re-upload the file.
15. Finalize and publish the release (change it from draft to public).
16. Ensure that the GitHub Actions for `Publish Python 🐍 distributions 📦 to PyPI and TestPyPI` and `Build and push multi-platform docker images` are functioning correctly. Check that the `PyPI` modules published on `https://pypi.org/project/pyln-*` and that the Docker image has been uploaded to Docker Hub.
17. Announce the hotfix release in the core-lightning release-chat channel on Discord and on [BuildOnL2](https://community.corelightning.org/c/general-questions/).
