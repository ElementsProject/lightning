/* Licensed under BSD-MIT - see LICENSE file for details */
#ifndef CCAN_PATH_H
#define CCAN_PATH_H
#include <ccan/tal/tal.h>
#include <stdbool.h>

/**
 * path_cwd - get current directory.
 * @ctx: the context to tal from
 *
 * Returns NULL and sets errno on error.
 */
char *path_cwd(const tal_t *ctx);

/**
 * path_readlink - get a symbolic link contents
 * @ctx: the context to tal the result from
 * @link: the link to read (can be take())
 *
 * Returns NULL and sets errno on error, otherwise returns nul-terminated
 * link contents.
 */
char *path_readlink(const tal_t *ctx, const char *link TAKES);

/**
 * path_canon - return the canonical absolute pathname.
 * @ctx: the context to tal the result from.
 * @a: path to canonicalize (can be take())
 *
 * Returns NULL and sets errno on error, otherwise returns an absolute
 * path with no symbolic links and no extra separators (ie. as per
 * realpath).
 */
char *path_canon(const tal_t *ctx, const char *a TAKES);

/**
 * path_simplify - remove double-/, ./ and some ../, plus trailing /.
 * @ctx: the context to tal the result from
 * @a: path to simplify (can be take())
 *
 * Unlike path_canon(), this routine does not convert a path to absolute
 * terms or remove symlinks, but it does neaten it by removing extraneous
 * parts.
 */
char *path_simplify(const tal_t *ctx, const char *a TAKES);

/**
 * path_join - attach one path to another.
 * @ctx: the context to tal the result from
 * @base: the path to start at (can be take())
 * @a: the path to head from there (can be take())
 *
 * If @a is an absolute path, return a copy of it.  Otherwise, attach
 * @a to @base.
 */
char *path_join(const tal_t *ctx, const char *base TAKES, const char *a TAKES);

/**
 * path_pushd - save old dir and change to a new one.
 * @ctx: the context to tal the result from
 * @dir: the directory to return to (can be take())
 */
struct path_pushd *path_pushd(const tal_t *ctx, const char *dir TAKES);

/**
 * path_popd - return to old, path_pushd dir.
 * @olddir: the return from a previous path_pushd.
 *
 * Returns false and sets errno if it fails.
 */
bool path_popd(struct path_pushd *olddir);

/**
 * path_rel - get relative path from a to b.
 * @ctx: the context to tal the result from.
 * @fromdir: the starting location (can be take())
 * @to: the destination location (can be take())
 *
 * This returns a relative path which leads from @fromdir (assumed to be a
 * directory) to @to.  If @ctx it TAL_TAKE, frees both @fromdir and @to.
 *
 * Example:
 *	char *path = path_rel(NULL, "/tmp", "/");
 *	assert(strcmp(path, "..") == 0);
 */
char *path_rel(const tal_t *ctx,
	       const char *fromdir TAKES, const char *to TAKES);

/**
 * path_basename - get trailing filename part of path
 * @ctx: the context to tal the result from
 * @path: the path (can be take())
 *
 * This follows SUSv2:
 *    path         dirname    basename
 *    "/usr/lib"    "/usr"    "lib"
 *     "/usr/"       "/"       "usr"
 *     "usr"         "."       "usr"
 *     "/"           "/"       "/"
 *     "."           "."       "."
 *     ".."          "."       ".."
 *
 * See Also:
 *	path_dirname()
 */
char *path_basename(const tal_t *ctx, const char *path TAKES);

/**
 * path_dirname - get the directory part of path
 * @ctx: the context to tal the result from.
 * @path: the path (can be take())
 *
 * This follows SUSv2.
 *
 * See Also:
 *	path_basename()
 */
char *path_dirname(const tal_t *ctx, const char *path TAKES);

/**
 * path_is_abs - is a path absolute?
 * @path: the path to examine.
 */
bool path_is_abs(const char *path);

/**
 * path_is_file - is a path an existing file (or long to one)?
 * @path: the path to examine.
 */
bool path_is_file(const char *path);

/**
 * path_is_file - is a path an existing directory (or long to one)?
 * @path: the path to examine.
 */
bool path_is_dir(const char *path);

/**
 * path_split - split a path into its pathname components
 * @ctx: the context to tal the result from
 * @path: the path (can be take())
 *
 * This returns the sections of a path, such that joining them with /
 * will restore the original path.  This means that the resulting
 * strings will never contain / unless the input path was entirely one
 * or more "/" characters.
 *
 * The final char * in the array will be NULL.
 *
 * See Also:
 *	strjoin()
 */
char **path_split(const tal_t *ctx, const char *path TAKES);

/**
 * path_ext_off - get offset of the extension within a pathname.
 * @path: the path
 *
 * This returns the offset of the final . in the pathname (ie.
 * path[path_ext_off(path)] == '.') or the length of the string
 * if there is no extension.
 *
 * Note that if the only . in the basename is at the start
 * (eg. /home/person/.bashrc), that is not considered an extension!
 */
size_t path_ext_off(const char *path);

/* Separator constants */
#define PATH_SEP_STR "/"
#define PATH_SEP (PATH_SEP_STR[0])

#endif /* CCAN_PATH_H */
