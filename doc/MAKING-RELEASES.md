## Release checklist

Here's a checklist for the release process.

### Leading Up To The Release

1. Talk to team about whether there are any changes which MUST go in
   this release which may cause delay.
2. Look through outstanding issues, to identify any problems that might
   be necessary to fixup before the release. Good candidates are reports
   of the project not building on different architectures or crashes.
3. Identify a good lead for each outstanding issue, and ask them about
   a fix timeline.
4. Create a milestone for the *next* release on Github, and go though
   open issues and PRs and mark accordingly.
5. Ask (via email) the most significant contributor who has not
   already named a release to name the release (use 
   `devtools/credit --verbose v<PREVIOUS-VERSION>` to find this contributor).
   CC previous namers and team.

### Preparing for -rc1

1. Check that `CHANGELOG.md` is well formatted, ordered in areas,
   covers all signficant changes, and sub-ordered approximately by user impact
   & coolness.
2. Use `devtools/changelog.py` to collect the changelog entries from pull
   request commit messages and merge them into the manually maintained
   `CHANGELOG.md`.  This does API queries to GitHub, which are severely
   ratelimited unless you use an API token: set the `GH_TOKEN` environment
   variable to a Personal Access Token from https://github.com/settings/tokens
3. Create a new CHANGELOG.md heading to `v<VERSION>rc1`, and create a link at
   the bottom. Note that you should exactly copy the date and name format from
   a previous release, as the `build-release.sh` script relies on this.
4. Update the contrib/pyln package versions: `make update-pyln-versions NEW_VERSION=<VERSION>`
5. Create a PR with the above.

### Releasing -rc1

1. Merge the above PR.
2. Tag it `git pull && git tag -s v<VERSION>rc1`. Note that you
   should get a prompt to give this tag a 'message'. Make sure you fill this in.
3. Confirm that the tag will show up for builds with `git describe`
4. Push the tag to remote `git push --tags`.
5. Announce rc1 release on core-lightning's release-chat channel on Discord
    & [BuildOnL2](https://community.corelightning.org/c/general-questions/).
6. Use `devtools/credit --verbose v<PREVIOUS-VERSION>` to get commits, days 
   and contributors data for release note.
7. Prepare draft release notes including information from above step, and share 
   with the team for editing.
8. Upgrade your personal nodes to the rc1, to help testing.
9. Follow [reproducible build](REPRODUCIBLE.md) for [Builder image setup](https://lightning.readthedocs.io/REPRODUCIBLE.html#builder-image-setup). It will create builder images `cl-repro-<codename>` which are required for the next step.
10. Run `tools/build-release.sh bin-Fedora-28-amd64 bin-Ubuntu sign` script to prepare required builds for the release. With `bin-Fedora-28-amd64 bin-Ubuntu sign`, it will build a zipfile, a non-reproducible Fedora, reproducible Ubuntu images. Once it is done, the script will sign the release contents and create SHA256SUMS and SHA256SUMS.asc in the release folder.
10. RC images are not uploaded on Docker. Hence they can be removed from the target list for RC versions. Each docker image takes approx. 90 minutes to bundle but it is highly recommended to test docker setup once, if you haven't done that before. Prior to building docker images, ensure that `multiarch/qemu-user-static` setup is working on your system as described [here](https://lightning.readthedocs.io/REPRODUCIBLE.html#setting-up-multiarch-qemu-user-static).

### Releasing -rc2, ..., -rcN

1. Change rc(N-1) to rcN in CHANGELOG.md.
2. Update the contrib/pyln package versions: `make update-pyln-versions NEW_VERSION=<VERSION>`
3. Add a PR with the rcN.
4. Tag it `git pull && git tag -s v<VERSION>rcN && git push --tags`
5. Announce tagged rc release on core-lightning's release-chat channel on Discord
    & [BuildOnL2](https://community.corelightning.org/c/general-questions/).
6. Upgrade your personal nodes to the rcN.

### Tagging the Release

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
   - Build reproducible Ubuntu-v18.04, Ubuntu-v20.04, Ubuntu-v22.04 images. Follow [link](https://lightning.readthedocs.io/REPRODUCIBLE.html#building-using-the-builder-image) for manually Building Ubuntu Images.
   - Build Docker images for amd64 and arm64v8
   - Create and sign checksums. Follow [link](https://lightning.readthedocs.io/REPRODUCIBLE.html#co-signing-the-release-manifest) for manually signing the release.
6. The tarballs may be owned by root, so revert ownership if necessary:
    `sudo chown ${USER}:${USER} *${VERSION}*`
7. Upload the resulting files to github and save as a draft.
    (https://github.com/ElementsProject/lightning/releases/)
8. Send `SHA256SUMS` & `SHA256SUMS.asc` files to the rest of the team to check and sign the release.
9. Team members can verify the release with the help of `build-release.sh`:
   9.1 Rename release captain's `SHA256SUMS` to `SHA256SUMS-v${VERSION}` and `SHA256SUMS.asc` to `SHA256SUMS-v${VERSION}.asc`.
   9.2 Copy them in the root folder (`lightning`).
   9.3 Run `tools/build-release.sh --verify`. It will create reproducible images, verify checksums and sign. 
   9.4 Send your signatures from `release/SHA256SUMS.new` to release captain.
   9.5 Or follow [link](https://lightning.readthedocs.io/REPRODUCIBLE.html#verifying-a-reproducible-build) for manual verification instructions.
10. Append signatures shared by the team into the `SHA256SUMS.asc` file, verify
    with `gpg --verify SHA256SUMS.asc` and include the file in the draft release.
11. `make pyln-release` to upload pyln modules to pypi.org.  This requires keys
    for each of pyln-client, pyln-proto, and pyln-testing accessible to poetry.
    This can be done by configuring the python keyring library along with a
    suitable backend.  Alternatively, the key can be set as an environment
    variable and each of the pyln releases can be built and published
    independently:
    - `export POETRY_PYPI_TOKEN_PYPI=<pyln-client token>`
    - `make pyln-release-client`
    - ... repeat for each pyln package.

### Performing the Release

1. Edit the GitHub draft and include the `SHA256SUMS.asc` file.
2. Publish the release as not a draft.
3. Announce the final release on core-lightning's release-chat channel on Discord
    & [BuildOnL2](https://community.corelightning.org/c/general-questions/).
4. Send a mail to c-lightning and lightning-dev mailing lists, using the
   same wording as the Release Notes in github.
5. Write release blog, post it on [Blockstream](https://blog.blockstream.com/) and announce the release on Twitter.

### Post-release

1. Look through PRs which were delayed for release and merge them.
2. Close out the Milestone for the now-shipped release.
3. Update this file with any missing or changed instructions.
