#!/usr/bin/env bash
# Check each commit in BASE..HEAD on its own, oldest first: build,
# check-source, unit tests, then the integration test files that commit
# touches.  Run it through make, so the tools come from the uv environment:
#
#   make check-commits [BASE_REF=origin/master]
#   make check-commits-full      # whole integration suite on every commit
#
# The branch is not rewritten.  Each commit is checked out detached and the
# original HEAD is restored afterwards, so tracked files must be clean.
#
# A commit that passes is recorded by tree, parent tree and configuration,
# so a rerun after fixing a later commit skips the earlier ones.
#
# Environment:
#   CHECK_COMMITS_PYTEST    touched (default), all, or none
#   CHECK_COMMITS_SKIP_TIP  1 to leave out the last commit
#   CHECK_COMMITS_CACHE     file listing passed commits (default: in .git;
#                           /dev/null to disable)
#   CHECK_COMMITS_LOGDIR    where step logs go (default: a new temp dir)
#   CHECK_COMMITS_JOBS      parallel make jobs (default: number of CPUs)
#   PYTEST_PAR              pytest workers (default: CHECK_COMMITS_JOBS)

set -u

orig=

die() {
	echo "check-commits: $*" >&2
	exit 1
}

tracked_changes() {
	git status --porcelain --untracked-files=no --ignore-submodules=all
}

submodule_changes() {
	# shellcheck disable=SC2016 # Expanded by the shell in each submodule.
	git submodule foreach --quiet --recursive \
		'test -z "$(git status --porcelain)" || echo "$displaypath"'
}

update_submodules() {
	git submodule sync --quiet --recursive
	git submodule update --quiet --init --recursive
}

restore_head() {
	if [ -n "$orig" ] && ! git checkout -q "$orig"; then
		echo "check-commits: could not return to $orig, HEAD is still detached" >&2
	elif [ -n "$orig" ] && ! update_submodules; then
		echo "check-commits: returned to $orig, but could not restore its submodules" >&2
	fi
}

# Tracked files that a step rewrites are stale in the commit, and would
# block the checkout of the next one.
require_clean() {
	if [ -n "$(tracked_changes)" ]; then
		echo "check-commits: $1 changed tracked files, so this commit has them stale:" >&2
		tracked_changes >&2
		return 1
	fi
}

# Run one step with its output in a log, and show the tail if it fails.
step() {
	local name=$1 log
	shift
	log="$logdir/$label-$name.log"
	printf '  %-12s ' "$name"
	if "$@" > "$log" 2>&1; then
		echo ok
		return 0
	fi
	echo FAILED
	tail -n 60 "$log"
	echo "check-commits: $name failed, full log in $log" >&2
	return 1
}

check_commit() {
	local sha=$1 tests

	step build make -j "$jobs" || return 1
	require_clean "the build" || return 1
	step check-source make -j "$jobs" check-source BASE_REF="$base" || return 1
	step check-units make -j "$jobs" check-units || return 1

	case "$pytest_mode" in
	none)
		;;
	all)
		step pytest make pytest || return 1
		;;
	touched)
		tests=$(git diff-tree --no-commit-id --name-only -r --diff-filter=d "$sha" -- 'tests/test_*.py' | tr '\n' ' ')
		if [ -n "$tests" ]; then
			step pytest make pytest PYTEST_TESTS="$tests" || return 1
		fi
		;;
	esac
	require_clean "the checks"
}

# Everything runs from main, so bash has read the whole file before the
# first checkout: an older commit may not have this script.
main() {
	local base commits total config messages key sha n=0 skipped=0

	cd "$(git rev-parse --show-toplevel)" || exit 1

	base=${1:-origin/master}
	pytest_mode=${CHECK_COMMITS_PYTEST:-touched}
	case "$pytest_mode" in
	touched|all|none)
		;;
	*)
		die "CHECK_COMMITS_PYTEST must be touched, all or none"
		;;
	esac
	jobs=${CHECK_COMMITS_JOBS:-$(getconf _NPROCESSORS_ONLN)}
	export PYTEST_PAR=${PYTEST_PAR:-$jobs}
	cache=${CHECK_COMMITS_CACHE:-$(git rev-parse --git-path check-commits-passed)}
	# The sub-makes take their options from here, not from a make that ran us.
	unset MAKEFLAGS MFLAGS MAKELEVEL

	git rev-parse -q --verify "$base^{commit}" > /dev/null || die "no such base: $base"
	[ -z "$(tracked_changes)" ] || die "tracked files have changes, commit or stash them first"
	[ -z "$(submodule_changes)" ] || die "submodules have changes, commit or stash them first"
	if git submodule status --recursive | grep -q '^[+U]'; then
		die "a submodule is not at the revision recorded by HEAD"
	fi

	commits=$(git rev-list --reverse "$base..HEAD") || exit 1
	if [ "${CHECK_COMMITS_SKIP_TIP:-0}" = 1 ]; then
		commits=$(printf '%s\n' "$commits" | sed '$d')
	fi
	if [ -z "$commits" ]; then
		echo "check-commits: no commits to check in $base..HEAD"
		exit 0
	fi
	total=$(printf '%s\n' "$commits" | wc -l | tr -d ' ')

	logdir=${CHECK_COMMITS_LOGDIR:-$(mktemp -d "${TMPDIR:-/tmp}/check-commits.XXXXXX")}
	mkdir -p "$logdir" || exit 1

	orig=$(git symbolic-ref -q --short HEAD || git rev-parse HEAD)
	# A check may need to see what the rest of the branch does with a commit.
	CHECK_COMMITS_TIP=$(git rev-parse HEAD) || exit 1
	export CHECK_COMMITS_TIP
	trap restore_head EXIT
	trap 'exit 130' INT TERM

	for sha in $commits; do
		n=$((n + 1))
		label=$(printf '%02d-%s' "$n" "$(git rev-parse --short "$sha")")
		echo "[$n/$total] $(git log -1 --format='%h %s' "$sha")"

		config=$(git hash-object config.vars 2> /dev/null || echo unconfigured)
		messages=$(git log --reverse --format='%B%x00' "$base..$sha" | git hash-object --stdin)
		key="$(git rev-parse "$sha^{tree}") $(git rev-parse -q --verify "$sha^^{tree}" || echo root) $pytest_mode $config $messages"
		if grep -qxF "$key" "$cache" 2> /dev/null; then
			echo "  already passed"
			skipped=$((skipped + 1))
			continue
		fi

		git checkout -q --detach "$sha" || exit 1
		if ! step submodules update_submodules; then
			echo "check-commits: FAILED to update submodules at $(git log -1 --format='%h %s' "$sha")" >&2
			exit 1
		fi
		if ! check_commit "$sha"; then
			echo "check-commits: FAILED at $(git log -1 --format='%h %s' "$sha")" >&2
			exit 1
		fi
		echo "$key" >> "$cache"
	done

	echo "check-commits: all $total commits pass ($skipped already passed in an earlier run)"
}

main "$@"
