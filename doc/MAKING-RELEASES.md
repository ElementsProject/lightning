## Release checklist

Here's a checklist for the release process.

### Leading Up To The Release

1. Talk to team about whether there are any changes which MUST go in
   this release which may cause delay.
2. Create a milestone for the *next* release, and go though issues and PR
   and mark accordingly.
3. Ask the most significant contributor who has not already named a
   release to name the release.  CC previous namers and team.

### Prepering for -rc1

1. Check that CHANGELOG.md covers all signficant changes.
2. Update the CHANGELOG.md with [Unreleased] changed to -rc1, and add a new
   footnote.
3. Create a PR with the above.

### Releasing -rc1

1. Merge the PR above.
2. Tag it `git pull && git tag -s v<VERSION>rc1 && git push --tags`
3. Update the /topic on #c-lightning on Freenode.
4. Prepare draft release notes, and share with team for editing.
5. Upgrade your personal nodes to the rc1, to help testing.

### Tagging the Release

1. Update the CHANGELOG.md; remove -rc1 in both places, and move the
   [Unreleased] footnote URL from the previous version to the
   about-to-be-released version.
2. Commit that, then `git tag -s v<VERSION>  && git push --tags`.
3. Run `tools/build-release.sh` to create the images, `SHA256SUMS` and
   signatures into release/.
4. Upload the files resulting files to github and
   save as a draft.
   (https://github.com/ElementsProject/lightning/releases/)
5. Ping the rest of the team to check the SHA256SUMS file and have them
   `gpg -sb --armor SHA256SUMS`.
6. Append the signatures into a file called `SHA256SUMS.asc`, verify
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
