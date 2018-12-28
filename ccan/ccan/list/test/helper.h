/* These are in a separate C file so we can test undefined structures. */
struct opaque;
typedef struct opaque opaque_t;

opaque_t *create_opaque_blob(void);
bool if_blobs_know_the_secret(opaque_t *blob);
void destroy_opaque_blob(opaque_t *blob);


