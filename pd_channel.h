/*
 * Poon-Dryja Generalized Channel Implementation.
 *
 * It's fairly symmetrical, but for clarity the api divides into
 * client and server.
 */

/* Construct the inputs they want to use. */
struct input *pd_ask_anchor_inputs(void);




/* Client creates an unsigned transaction using their own funds: */
struct tx *client_anchor_tx(struct input *spend, u64 amount);

/* Then, from that we create an updatable commitment transaction,
 * with two outputs (one is zero val). */


