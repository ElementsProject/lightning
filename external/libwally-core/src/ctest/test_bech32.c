#include "config.h"

#include <wally_core.h>
#include <wally_address.h>
#include <stdio.h>
#include <stdbool.h>

static const char *invalid = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefg";

static bool check_segwit_to_bytes(void)
{
    unsigned char *mem = calloc(90, sizeof(unsigned char));
    size_t written;
    int ret;

    if (!mem)
        return false;

    ret = wally_addr_segwit_to_bytes(invalid, "tb", 0, mem, 90, &written);

    if (ret != WALLY_EINVAL)
        return false;

    free(mem);

    return true;
}

int main(void)
{
    bool tests_ok = true;

    if (!check_segwit_to_bytes()) {
        printf("check_segwit_to_bytes test failed!\n");
        tests_ok = false;
    }

    return tests_ok ? 0 : 1;
}
