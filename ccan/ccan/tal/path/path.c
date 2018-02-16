/* Licensed under BSD-MIT - see LICENSE file for details */
#include <ccan/tal/path/path.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

char *path_cwd(const tal_t *ctx)
{
	size_t len = 64;
	char *cwd;

	/* *This* is why people hate C. */
	cwd = tal_arr(ctx, char, len);
	while (cwd && !getcwd(cwd, len)) {
		if (errno != ERANGE || !tal_resize(&cwd, len *= 2))
			cwd = tal_free(cwd);
	}
	return cwd;
}

char *path_join(const tal_t *ctx, const char *base, const char *a)
{
	char *ret = NULL;
	size_t len;

	if (unlikely(!a) && taken(a)) {
		if (taken(base))
			tal_free(base);
		return NULL;
	}

	if (a[0] == PATH_SEP) {
		if (taken(base))
			tal_free(base);
		return tal_strdup(ctx, a);
	}

	if (unlikely(!base) && taken(base))
		goto out;

	len = strlen(base);
	ret = tal_dup_arr(ctx, char, base, len, 1 + strlen(a) + 1);
	if (!ret)
		goto out;
	if (len != 0 && ret[len-1] != PATH_SEP)
		ret[len++] = PATH_SEP;
	strcpy(ret + len, a);

out:
	if (taken(a))
		tal_free(a);
	return ret;
}

#if HAVE_FCHDIR
struct path_pushd {
	int fd;
};

static void pushd_destroy(struct path_pushd *pushd)
{
	close(pushd->fd);
}

struct path_pushd *path_pushd(const tal_t *ctx, const char *dir)
{
	struct path_pushd *old = tal(ctx, struct path_pushd);

	if (!old)
		return NULL;

	if (unlikely(!dir) && taken(dir))
		return tal_free(old);

	if (!tal_add_destructor(old, pushd_destroy))
		old = tal_free(old);
	else {
		old->fd = open(".", O_RDONLY);
		if (old->fd < 0)
			old = tal_free(old);
		else if (chdir(dir) != 0)
			old = tal_free(old);
	}

	if (taken(dir))
		tal_free(dir);
	return old;
}

bool path_popd(struct path_pushd *olddir)
{
	bool ok = (fchdir(olddir->fd) == 0);

	tal_free(olddir);
	return ok;
}
#else
struct path_pushd {
	const char *olddir;
};

struct path_pushd *path_pushd(const tal_t *ctx, const char *dir)
{
	struct path_pushd *old = tal(ctx, struct path_pushd);

	if (!old)
		return NULL;

	old->olddir = path_cwd(old);
	if (unlikely(!old->olddir))
		old = tal_free(old);
	else if (unlikely(!dir) && is_taken(dir))
		old = tal_free(old);
	else if (chdir(dir) != 0)
		old = tal_free(old);

	if (taken(dir))
		tal_free(dir);

	return old;
}

bool path_popd(struct path_pushd *olddir)
{
	bool ok = (chdir(olddir->olddir) == 0);

	tal_free(olddir);
	return ok;
}
#endif /* !HAVE_FCHDIR */

char *path_canon(const tal_t *ctx, const char *a)
{
#if 0
	char *oldcwd, *path, *p;
	void *tmpctx;
	size_t len;
	struct path_pushd *olddir;

	/* A good guess as to size. */
	len = strlen(a) + 1;
	if (a[0] != PATH_SEP) {
		tmpctx = oldcwd = path_cwd(ctx);
		if (!oldcwd)
			return NULL;
		len += strlen(oldcwd) + strlen(PATH_SEP_STR);

		path = tal_array(tmpctx, char, len);
		if (!path)
			goto out;

		len = strlen(oldcwd);
		memcpy(path, oldcwd, len);
		path[len++] = PATH_SEP;
	} else {
		tmpctx = path = tal_array(ctx, char, len);
		if (!path)
			return NULL;
		len = 0;
	}
	strcpy(path + len, a);

	p = strrchr(path, PATH_SEP);
	*p = '\0';

	olddir = path_pushd(tmpctx, path);
	if (!olddir)
		goto out;

	/* Make OS canonicalize path for us. */
	path = path_cwd(tmpctx);
	if (!path)
		goto out;

	/* Append rest of old path. */
	len = strlen(p+1);
	if (len) {
		size_t oldlen = tal_array_length(path);
		if (path[oldlen-1] != PATH_SEP) {
			/* Include / to append. */
			*p = PATH_SEP;
			p--;
			len++;
		}
		path = tal_realloc(NULL, path, char, oldlen+len+1);
		if (!path)
			goto out;
		memcpy(path + oldlen, p, len+1);
	}

	path = tal_steal(ctx, path);
out:
	/* This can happen if old cwd is deleted. */
	if (!path_popd(olddir))
		path = tal_free(path);

	tal_free(tmpctx);
	return path;
#else
	char *path;
	if (unlikely(!a) && is_taken(a))
		path = NULL;
	else {
		path = tal_arr(ctx, char, PATH_MAX);
		if (path && !realpath(a, path))
			path = tal_free(path);
	}
	if (taken(a))
		tal_free(a);
	return path;
#endif
}

/* Symlinks make this hard! */
char *path_rel(const tal_t *ctx, const char *from, const char *to)
{
	char *cfrom, *cto, *ret, *p;
	tal_t *tmpctx;
	size_t common, num_back, i, postlen;

	/* This frees from if we're supposed to take it. */
	tmpctx = cfrom = path_canon(ctx, from);
	if (!cfrom)
		goto fail_take_to;

	/* From is a directory, so we append / to it. */
	if (!streq(cfrom, PATH_SEP_STR)) {
		if (!tal_resize(&cfrom, strlen(cfrom)+2))
			goto fail_take_to;
		tmpctx = cfrom;
		strcat(cfrom, PATH_SEP_STR);
	}

	/* This frees to if we're supposed to take it. */
	cto = path_canon(tmpctx, to);
	if (!cto) {
		ret = NULL;
		goto out;
	}

	/* How much is in common? */
	for (common = i = 0; cfrom[i] && cto[i]; i++) {
		if (cfrom[i] != cto[i])
			break;
		if (cfrom[i] == PATH_SEP)
			common = i + 1;
	}

	/* Skip over / if matches end of other path.  */
	if (!cfrom[i] && cto[i] == PATH_SEP) {
		cto++;
		common = i;
	} else if (!cto[i] && cfrom[i] == PATH_SEP) {
		cfrom++;
		common = i;
	}

	/* Normalize so strings point past common area. */
	cfrom += common;
	cto += common;

	/* One .. for every path element remaining in 'from', to get
	 * back to common prefix.  Then the rest of 'to'. */
	num_back = strcount(cfrom, PATH_SEP_STR);
	postlen = strlen(cto) + 1;

	/* Nothing left?  That's ".". */
	if (num_back == 0 && postlen == 1) {
		ret = tal_strdup(ctx, ".");
		goto out;
	}

	ret = tal_arr(ctx, char,
		      strlen(".." PATH_SEP_STR) * num_back + postlen);
	if (!ret)
		goto out;

	for (i = 0, p = ret; i < num_back; i++, p += strlen(".." PATH_SEP_STR))
		memcpy(p, ".." PATH_SEP_STR, strlen(".." PATH_SEP_STR));
	/* Nothing to append?  Trim the final / */
	if (postlen == 1)
		p--;
	memcpy(p, cto, postlen);

out:
	tal_free(tmpctx);
	return ret;

fail_take_to:
	if (taken(to))
		tal_free(to);
	ret = NULL;
	goto out;
}

 char *path_readlink(const tal_t *ctx, const char *linkname)
 {
	ssize_t len, maxlen = 64; /* good first guess. */
	char *ret = NULL;

	if (unlikely(!linkname) && is_taken(linkname))
		goto fail;

	ret = tal_arr(ctx, char, maxlen + 1);

	while (ret) {
		len = readlink(linkname, ret, maxlen);
		if (len < 0)
			goto fail;
		if (len < maxlen)
			break;

		if (!tal_resize(&ret, maxlen *= 2 + 1))
			goto fail;
	}

	if (ret)
		ret[len] = '\0';

out:
	if (taken(linkname))
		tal_free(linkname);

	return ret;

fail:
	ret = tal_free(ret);
	goto out;
}

char *path_simplify(const tal_t *ctx, const char *path)
{
	size_t i, j, start, len;
	char *ret;
	bool ended = false;

	ret = tal_strdup(ctx, path);
	if (!ret)
		return NULL;

	/* Always need first / if there is one. */
	if (ret[0] == PATH_SEP)
		start = 1;
	else
		start = 0;

	for (i = j = start; !ended; i += len) {
		/* Get length of this segment, including terminator. */
		for (len = 0; ret[i+len] != PATH_SEP; len++) {
			if (!ret[i+len]) {
				ended = true;
				break;
			}
		}
		len++;

		/* Empty segment is //; ignore first one. */
		if (len == 1)
			continue;

		/* Always ignore slashdot. */
		if (len == 2 && ret[i] == '.')
			continue;

		/* .. => remove previous if there is one, unless symlink. */
		if (len == 3 && ret[i] == '.' && ret[i+1] == '.') {
			struct stat st;

			if (j > start) {
				/* eg. /foo/, foo/ or foo/bar/ */
				assert(ret[j-1] == PATH_SEP);
				ret[j-1] = '\0';

				/* Avoid stepping back over ..! */
				if (streq(ret, "..")
				    || strends(ret, PATH_SEP_STR"..")) {
					ret[j-1] = PATH_SEP;
					goto copy;
				}

				if (lstat(ret, &st) == 0
				    && !S_ISLNK(st.st_mode)) {
					char *sep = strrchr(ret, PATH_SEP);
					if (sep)
						j = sep - ret + 1;
					else
						j = 0;
				}
				continue;
			} else if (start) {
				/* /.. => / */
				j = 1;
				/* nul term in case we're at end */
				ret[1] = '\0';
				continue;
			}
		}

	copy:
		memmove(ret + j, ret + i, len);
		/* Don't count nul terminator. */
		j += len - ended;
	}

	/* Empty string created by ../ elimination. */
	if (j == 0) {
		ret[0] = '.';
		ret[1] = '\0';
	} else if (j > 1 && ret[j-1] == PATH_SEP) {
		ret[j-1] = '\0';
	} else
		ret[j] = '\0';

	return ret;
}

char *path_basename(const tal_t *ctx, const char *path)
{
	const char *sep;
	char *ret;

	if (unlikely(!path) && taken(path))
		return NULL;

	sep = strrchr(path, PATH_SEP);
	if (!sep)
		return tal_strdup(ctx, path);

	/* Trailing slashes need to be trimmed. */
	if (!sep[1]) {
		const char *end;

		for (end = sep; end != path; end--)
			if (*end != PATH_SEP)
				break;

		/* Find *previous* / */
		for (sep = end; sep >= path && *sep != PATH_SEP; sep--);

		/* All /?  Just return / */
		if (end == sep)
			ret = tal_strdup(ctx, PATH_SEP_STR);
		else
			ret = tal_strndup(ctx, sep+1, end - sep);
	} else
		ret = tal_strdup(ctx, sep + 1);

	if (taken(path))
		tal_free(path);
	return ret;
}

/* This reuses str if we're to take it. */
static char *fixed_string(const tal_t *ctx,
			  const char *str, const char *path)
{
	char *ret = tal_dup_arr(ctx, char, path, 0, strlen(str)+1);
	if (ret)
		strcpy(ret, str);
	return ret;
}

char *path_dirname(const tal_t *ctx, const char *path)
{
	const char *sep;

	if (unlikely(!path) && taken(path))
		return NULL;

	sep = strrchr(path, PATH_SEP);
	if (!sep)
		return fixed_string(ctx, ".", path);

	/* Trailing slashes need to be trimmed. */
	if (!sep[1]) {
		const char *end;

		for (end = sep; end != path; end--)
			if (*end != PATH_SEP)
				break;

		/* Find *previous* / */
		for (sep = end; sep > path && *sep != PATH_SEP; sep--);
	}

	/* In case there are multiple / in a row. */
	while (sep > path && sep[-1] == PATH_SEP)
		sep--;

	if (sep == path) {
		if (path_is_abs(path))
			return tal_strndup(ctx, path, 1);
		else
			return fixed_string(ctx, ".", path);
	}
	return tal_strndup(ctx, path, sep - path);
}

bool path_is_abs(const char *path)
{
	return path[0] == PATH_SEP;
}

bool path_is_file(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

bool path_is_dir(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

char **path_split(const tal_t *ctx, const char *path)
{
	bool empty = path && !path[0];
	char **ret = tal_strsplit(ctx, path, PATH_SEP_STR, STR_NO_EMPTY);

	/* Handle the "/" case */
	if (ret && !empty && !ret[0]) {
		if (!tal_resize(&ret, 2))
			ret = tal_free(ret);
		else {
			ret[1] = NULL;
			ret[0] = tal_strdup(ret, PATH_SEP_STR);
			if (!ret[0])
				ret = tal_free(ret);
		}
	}

	return ret;
}

size_t path_ext_off(const char *path)
{
	const char *dot, *base;

	dot = strrchr(path, '.');
	if (dot) {
		base = strrchr(path, PATH_SEP);
		if (!base)
			base = path;
		else
			base++;
		if (dot > base)
			return dot - path;
	}
	return strlen(path);
}
