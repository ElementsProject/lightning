#ifndef LIBWALLY_CORE_SCRIPT_INTERNAL_H
#define LIBWALLY_CORE_SCRIPT_INTERNAL_H 1

#include <stdbool.h>

/* Get the size of a push from the script push opcode(s) */
int script_get_push_size_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    size_t *size);

/* Get the size of a push opcode from the script push opcode(s) */
int script_get_push_opcode_size_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    size_t *size);

/* Get OP_N */
bool script_is_op_n(unsigned char op, bool allow_zero, size_t *n);

/* Convert 0-16 to OP_<N> */
size_t value_to_op_n(uint64_t v);

/* Get the length of a script pushing 'n' bytes */
size_t script_get_push_size(size_t n);

#endif /* LIBWALLY_CORE_SCRIPT_INTERNAL_H */
