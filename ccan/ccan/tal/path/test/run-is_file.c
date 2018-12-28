#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void)
{
	char cwd[1024], *path, *ctx = tal_strdup(NULL, "ctx");

	plan_tests(7);

	if (!getcwd(cwd, sizeof(cwd)))
		abort();

	unlink("run-is_file-dir-link");
	unlink("run-is_file-file-link");
	unlink("run-is_file-dir/file");
	rmdir("run-is_file-dir");
	if (mkdir("run-is_file-dir", 0700) != 0)
		abort();
	if (symlink("run-is_file-dir", "run-is_file-dir-link") != 0)
		abort();
	if (symlink("run-is_file-dir/file", "run-is_file-file-link") != 0)
		abort();
	close(open("run-is_file-dir/file", O_WRONLY|O_CREAT, 0600));

	ok1(!path_is_file("run-is_file-dir-link"));
	ok1(path_is_file("run-is_file-file-link"));
	ok1(path_is_file("run-is_file-dir/file"));
	ok1(!path_is_file("run-is_file-dir"));
	ok1(!path_is_file("run-is_file-nonexist"));

	path = path_join(ctx, cwd, "run-is_file-dir/file");
	ok1(path_is_file(path));
	ok1(!path_is_file(cwd));

	tal_free(ctx);

	return exit_status();
}
