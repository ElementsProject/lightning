---
title: "Contributor Workflow"
slug: "contributor-workflow"
excerpt: "Learn the practical process and guidelines for contributing."
hidden: false
createdAt: "2022-12-09T09:57:57.245Z"
updatedAt: "2023-04-22T13:00:38.252Z"
---
## Build and Development

Install the following dependencies for best results:

```shell
sudo apt update
sudo apt install valgrind cppcheck shellcheck libsecp256k1-dev libpq-dev
```



Re-run `configure` and build using `make`:

```shell
./configure --enable-developer
make -j$(nproc)
```



## Debugging

You can build Core Lightning with `DEVELOPER=1` to use dev commands listed in `cli/lightning-cli help`. `./configure --enable-developer` will do that. You can log console messages with log_info() in lightningd and status_debug() in other subdaemons.

You can debug crashing subdaemons with the argument `--dev-debugger=channeld`, where `channeld` is the subdaemon name.  It will run `gnome-terminal` by default with a gdb attached to the subdaemon when it starts.  You can change the terminal used by setting the `DEBUG_TERM` environment variable, such as `DEBUG_TERM="xterm -e"` or `DEBUG_TERM="konsole -e"`.

It will also print out (to stderr) the gdb command for manual connection.  The subdaemon will be stopped (it sends itself a `SIGSTOP`); you'll need to `continue` in gdb.

```shell
./configure --enable-developer
make -j$(nproc)
```



## Making BOLT Modifications

All of code for marshalling/unmarshalling BOLT protocol messages is generated directly from the spec. These are pegged to the BOLTVERSION, as specified in `Makefile`.

## Source code analysis

An updated version of the NCC source code analysis tool is available at

<https://github.com/bitonic-cjp/ncc>

It can be used to analyze the lightningd source code by running `make clean && make ncc`. The output (which is built in parallel with the binaries) is stored in .nccout files. You can browse it, for instance, with a command like `nccnav lightningd/lightningd.nccout`.

## Subtleties

There are a few subtleties you should be aware of as you modify deeper parts of the code:

- `ccan/structeq`'s STRUCTEQ_DEF will define safe comparison function `foo_eq()` for struct `foo`, failing the build if the structure has implied padding.
- `command_success`, `command_fail`, and `command_fail_detailed` will free the `cmd` you pass in.  
  This also means that if you `tal`-allocated anything from the `cmd`, they will also get freed at those points and will no longer be accessible afterwards.
- When making a structure part of a list, you will instance a `struct list_node`. This has to be the _first_ field of the structure, or else `dev-memleak` command will think your structure has leaked.

## Protocol Modifications

The source tree contains CSV files extracted from the v1.0 BOLT specifications (wire/extracted_peer_wire_csv and wire/extracted_onion_wire_csv).  You can regenerate these by first deleting the local copy(if any) at directory .tmp.bolts, setting `BOLTDIR` and `BOLTVERSION` appropriately, and finally running `make
extract-bolt-csv`. By default the bolts will be retrieved from the directory `../bolts` and a recent git version.

e.g., `make extract-bolt-csv BOLTDIR=../bolts BOLTVERSION=ee76043271f79f45b3392e629fd35e47f1268dc8`

## Release checklist

Here's a checklist for the release process.

### Leading Up To The Release

1. Talk to team about whether there are any changes which MUST go in this release which may cause delay.
2. Look through outstanding issues, to identify any problems that might be necessary to fixup before the release. Good candidates are reports of the project not building on different architectures or crashes.
3. Identify a good lead for each outstanding issue, and ask them about a fix timeline.
4. Create a milestone for the _next_ release on Github, and go though open issues and PRs and mark accordingly.
5. Ask (via email) the most significant contributor who has not already named a release to name the release (use devtools/credit to find this contributor). CC previous namers and team.

### Preparing for -rc1

1. Check that `CHANGELOG.md` is well formatted, ordered in areas, covers all significant changes, and sub-ordered approximately by user impact & coolness.
2. Use `devtools/changelog.py` to collect the changelog entries from pull request commit messages and merge them into the manually maintained `CHANGELOG.md`.  This does API queries to GitHub, which are severely ratelimited unless you use an API token: set the `GH_TOKEN` environment variable to a Personal Access Token from <https://github.com/settings/tokens>
3. Create a new CHANGELOG.md heading to `v<VERSION>rc1`, and create a link at the bottom. Note that you should exactly copy the date and name format from a previous release, as the `build-release.sh` script relies on this.
4. Update the contrib/pyln package versions: `make update-pyln-versions NEW_VERSION=<VERSION>`
5. Create a PR with the above.

### Releasing -rc1

1. Merge the above PR.
2. Tag it `git pull && git tag -s v<VERSION>rc1`. Note that you should get a prompt to give this tag a 'message'. Make sure you fill this in.
3. Confirm that the tag will show up for builds with `git describe`
4. Push the tag to remote `git push --tags`.
5. Update the /topic on #c-lightning on Libera.
6. Prepare draft release notes (see devtools/credit), and share with team for editing.
7. Upgrade your personal nodes to the rc1, to help testing.
8. Test `tools/build-release.sh` to build the non-reproducible images and reproducible zipfile.
9. Use the zipfile to produce a [Reproducible builds](doc:repro).

### Releasing -rc2, etc

1. Change rc1 to rc2 in CHANGELOG.md.
2. Add a PR with the rc2.
3. Tag it `git pull && git tag -s v<VERSION>rc2 && git push --tags`
4. Update the /topic on #c-lightning on Libera.
5. Upgrade your personal nodes to the rc2.

### Tagging the Release

1. Update the CHANGELOG.md; remove -rcN in both places, update the date and add title and namer.
2. Update the contrib/pyln package versions: `make update-pyln-versions NEW_VERSION=<VERSION>`
3. Add a PR with that release.
4. Merge the PR, then:
   1. `export VERSION=0.9.3`
   2. `git pull`
   3. `git tag -a -s v${VERSION} -m v${VERSION}`
   4. `git push --tags`
5. Run `tools/build-release.sh` to build the non-reproducible images and reproducible zipfile.
6. Use the zipfile to produce a [reproducible build](REPRODUCIBLE.md).
7. To create and sign checksums, start by entering the release dir: `cd release`
8. Create the checksums for signing: `sha256sum * > SHA256SUMS`
9. Create the first signature with `gpg -sb --armor SHA256SUMS`
10. The tarballs may be owned by root, so revert ownership if necessary:  
    `sudo chown ${USER}:${USER} *${VERSION}*`
11. Upload the resulting files to github and save as a draft.  
    (<https://github.com/ElementsProject/lightning/releases/>)
12. Ping the rest of the team to check the SHA256SUMS file and have them send their  
    `gpg -sb --armor SHA256SUMS`.
13. Append the signatures into a file called `SHA256SUMS.asc`, verify  
    with `gpg --verify SHA256SUMS.asc` and include the file in the draft  
    release.
14. `make pyln-release` to upload pyln modules to pypi.org.  This requires keys  
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
3. Update the /topic on #c-lightning on Libera.
4. Send a mail to c-lightning and lightning-dev mailing lists, using the same wording as the Release Notes in github.

### Post-release

1. Look through PRs which were delayed for release and merge them.
2. Close out the Milestone for the now-shipped release.
3. Update this file with any missing or changed instructions.