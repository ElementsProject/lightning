#ifndef LIBWALLY_CORE_TRANSACTION_SHARED_H
#define LIBWALLY_CORE_TRANSACTION_SHARED_H 1

#ifdef __cplusplus
extern "C" {
#endif

#define TX_CHECK_OUTPUT if (!output) return WALLY_EINVAL; else *output = NULL
#define TX_OUTPUT_ALLOC(typ) \
    *output = wally_calloc(sizeof(typ)); \
    if (!*output) return WALLY_ENOMEM; \
    result = (typ *) *output;

bool clone_data(void **dst, const void *src, size_t len);
bool clone_bytes(unsigned char **dst, const unsigned char *src, size_t len);
int replace_bytes(const unsigned char *bytes, size_t bytes_len,
                  unsigned char **bytes_out, size_t *bytes_len_out);
void *realloc_array(const void *src, size_t old_n, size_t new_n, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_TRANSACTION_SHARED_H */
