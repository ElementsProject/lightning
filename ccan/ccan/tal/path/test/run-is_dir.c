#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void)
{
	char cwd[1024], *path, *ctx = tal_strdup(NULL, "ctx");

	plan_tests(6);

	if (!getcwd(cwd, sizeof(cwd)))
		abort();

	unlink("run-is_dir-dir-link");
	unlink("run-is_dir-file-link");
	unlink("run-is_dir-dir/file");
	rmdir("run-is_dir-dir");
	if (mkdir("run-is_dir-dir", 0700) != 0)
		abort();
	if (symlink("run-is_dir-dir", "run-is_dir-dir-link") != 0)
		abort();
	if (symlink("run-is_dir-dir/file", "run-is_dir-file-link") != 0)
		abort();
	close(open("run-is_dir-dir/file", O_WRONLY|O_CREAT, 0600));

	ok1(path_is_dir("run-is_dir-dir-link"));
	ok1(!path_is_dir("run-is_dir-file-link"));
	ok1(!path_is_dir("run-is_dir-dir/file"));
	ok1(path_is_dir("run-is_dir-dir"));

	path = path_join(ctx, cwd, "run-is_dir-dir/file");
	ok1(!path_is_dir(path));
	ok1(path_is_dir(cwd));

	tal_free(ctx);

	return exit_status();
}
