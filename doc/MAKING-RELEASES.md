## Release checklist

Here's a checklist for the release process.

### Leading Up To The Release

1. Talk to team about whether there are any changes which MUST go in
   this release which may cause delay.
2. Create a milestone for the *next* release, and go though issues and PR
   and mark accordingly.
3. Ask the most significant contributor who has not already named a
   release to name the release (use devtools/credit).  CC previous namers
   and team.

### Prepering for -rc1

1. Check that CHANGELOG.md is well formatted, ordered in areas,
   covers all signficant changes, and sub-ordered approximately by user impact
   & coolness.
2. Update the CHANGELOG.md with [Unreleased] changed to -rc1.
3. Create a PR with the above.

### Releasing -rc1

1. Merge the PR above.
2. Tag it `git pull && git tag -s v<VERSION>rc1 && git push --tags`
3. Update the /topic on #c-lightning on Freenode.
4. Prepare draft release notes (see devtools/credit), and share with team for editing.
5. Upgrade your personal nodes to the rc1, to help testing.
6. Test `tools/build-release.sh` to build the non-reprodicible images
   and reproducible zipfile.
7. Use the zipfile to produce a [reproducible build](REPRODUCIBLE.md).

### Releasing -rc2, etc

1. Change rc1 to rc2 in CHANGELOG.md.
2. Add a PR with the rc2.
3. Tag it `git pull && git tag -s v<VERSION>rc2 && git push --tags`
4. Update the /topic on #c-lightning on Freenode.
5. Upgrade your personal nodes to the rc2.

### Tagging the Release

1. Update the CHANGELOG.md; remove -rcN in both places, and add an
   [Unreleased] footnote URL from this new version to HEAD.
2. Add a PR with that release.
3. Merge the PR, then `git pull && git tag -s v<VERSION> && git push --tags`.
4. Run `tools/build-release.sh` to build the non-reprodicible images
   and reproducible zipfile.
5. Use the zipfile to produce a [reproducible build](REPRODUCIBLE.md).
6. Create the checksums for signing: `sha256sum release/* > release/SHA256SUMS`
7. Create the first signature with `gpg -sb --armor release/SHA256SUMS`
8. Upload the files resulting files to github and
   save as a draft.
   (https://github.com/ElementsProject/lightning/releases/)
9. Ping the rest of the team to check the SHA256SUMS file and have them send their
   `gpg -sb --armor SHA256SUMS`.
10. Append the signatures into a file called `SHA256SUMS.asc`, verify
   with `gpg --verify SHA256SUMS.asc` and include the file in the draft
   release.

### Performing the Release

1. Edit the GitHub draft and include the `SHA256SUMS.asc` file.
2. Publish the release as not a draft.
3. Update the /topic on #c-lightning on Freenode.
4. Send a mail to c-lightning and lightning-dev mailing lists, using the
   same wording as the Release Notes in github.

### Post-release

1. Add a new '[Unreleased]' section the CHANGELOG.md with empty headers.
2. Look through PRs which were delayed for release and merge them.
