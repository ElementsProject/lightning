#include "config.h"
#include <ccan/asort/asort.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/bigsize.h>
#include <common/gossmap.h>
#include <common/setup.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static bool verbose = false;

/* All {numbers} are bigsize.
 *
 * <FILE> := <HEADER> <CHANNEL_ENDS> <CAPACITIES> <DISABLEDS> <HTLC_MINS> <HTLC_MAXS> <BASEFEES> <PROPFEES> <DELAYS>
 * <HEADER> := "GOSSMAP_COMPRESSv1\0"
 * <CHANNEL_ENDS> := {channel_count} {start_nodeidx}*{channel_count} {end_nodeidx}*{channel_count}
 *  This describes each attached channel, eg if there are two
 *  channels, node 0 to node 1 and node 0 to node 2, this would be:
 *   2 0 0 1 2
 *
 * <DISABLEDS> := <DISABLED>* {channel_count*2}
 * <DISABLED> := {chanidx}*2+{direction}
 *  Selection of disabled channels and directions, expected to only be a few.  Indexes into the
 *  first channel_ends array.  Terminated by invalid index.
 *
 * <CAPACITIES> := <CAPACITY_TEMPLATES> {channel_count}*{capacity_idx}
 * <CAPACITY_TEMPLATES> := {capacity_count} {channel_count}*{capacity}
 *  This is one satoshi amount per channel.
 *
 * <HTLC_MINS> := <HTLC_MIN_TEMPLATES> {channel_count*2}*{htlc_min_idx}
 * <HTLC_MIN_TEMPLATES> := {htlc_min_count} {htlc_min_count}*{htlc_min}
 *  These templates are all of the same form.  A set of values, followed by
 *  an index into these values for each direction of each channel, in order
 *  1. 0'th channel 1st direction
 *  2. 0'th channel 2nd direction
 *  3. 1'st channel 1st direction
 *  4. 1'st channel 2nd direction
 *
 * <HTLC_MAXS> := <HTLC_MAX_TEMPLATES> {channel_count*2}*{htlc_max_idx}
 *  Note that values 0 and 1 are special: 0 == channel capacity, 1 == 0.99 * channel capacity.
 * <HTLC_MAX_TEMPLATES> := {htlc_max_count} {htlc_max_count}*{htlc_max}
 * <BASEFEES> := <BASEFEE_TEMPLATES> {channel_count*2}*{basefee_idx}
 * <BASEFEE_TEMPLATES> := {basefee_count} {basefee_count}*{basefee}
 * <PROPFEES> := <PROPFEE_TEMPLATES> {channel_count*2}*{propfee_idx}
 * <PROPFEE_TEMPLATES> := {propfee_count} {propfee_count}*{propfee}
 * <DELAYS> := <DELAY_TEMPLATES> {channel_count*2}*{delay_idx}
 * <DELAY_TEMPLATES> := {delay_count} {delay_count}*{delay}
 */

#define GC_HEADER "GOSSMAP_COMPRESSv1"
#define GC_HEADERLEN (sizeof(GC_HEADER))

static int cmp_node_num_chans(struct gossmap_node *const *a,
			      struct gossmap_node *const *b,
			      void *unused)
{
	return (int)(*a)->num_chans - (int)(*b)->num_chans;
}

static void write_bigsize(int outfd, u64 val)
{
	u8 buf[BIGSIZE_MAX_LEN];
	size_t len;

	len = bigsize_put(buf, val);
	if (!write_all(outfd, buf, len))
		errx(1, "Writing bigsize");
}

static int cmp_u64(const u64 *a,
		   const u64 *b,
		   void *unused)
{
	if (*a > *b)
		return 1;
	else if (*a < *b)
		return -1;
	return 0;
}

static const u64 *deduplicate(const tal_t *ctx, const u64 *vals)
{
	u64 *sorted;
	u64 *dedup;
	size_t n;

	/* Sort and remove dups */
	sorted = tal_dup_talarr(tmpctx, u64, vals);
	asort(sorted, tal_count(sorted), cmp_u64, NULL);

	dedup = tal_arr(ctx, u64, tal_count(sorted));
	n = 0;
	dedup[n++] = sorted[0];
	for (size_t i = 1; i < tal_count(sorted); i++) {
		if (sorted[i] == dedup[n-1])
			continue;
		dedup[n++] = sorted[i];
	}
	tal_resize(&dedup, n);

	return dedup;
}

static size_t find_index(const u64 *template, u64 val)
{
	for (size_t i = 0; i < tal_count(template); i++) {
		if (template[i] == val)
			return i;
	}
	abort();
}

/* All templates are of the same form.  Output all the distinct values, then
 * write out which one is used by each channel */
static void write_template_and_values(int outfd, const u64 *vals, const char *what)
{
	/* Sort and remove dups */
	const u64 *template = deduplicate(tmpctx, vals);

	if (verbose)
		printf("%zu unique %s\n", tal_count(template), what);

	assert(tal_count(vals) >= tal_count(template));

	/* Write template. */
	write_bigsize(outfd, tal_count(template));
	for (size_t i = 0; i < tal_count(template); i++)
		write_bigsize(outfd, template[i]);

	/* Tie every channel into the template.  O(N^2) but who
	 * cares? */
	for (size_t i = 0; i < tal_count(vals); i++) {
		write_bigsize(outfd, find_index(template, vals[i]));
	}
}

static void write_bidir_perchan(int outfd,
				struct gossmap *gossmap,
				struct gossmap_chan **chans,
				u64 (*get_value)(struct gossmap *,
						 const struct gossmap_chan *,
						 int),
				const char *what)
{
	u64 *vals = tal_arr(tmpctx, u64, tal_count(chans) * 2);

	for (size_t i = 0; i < tal_count(chans); i++) {
		for (size_t dir = 0; dir < 2; dir++) {
			if (chans[i]->half[dir].enabled)
				vals[i*2+dir] = get_value(gossmap, chans[i], dir);
			else
				vals[i*2+dir] = 0;
		}
	}

	write_template_and_values(outfd, vals, what);
}

static u64 get_htlc_min(struct gossmap *gossmap,
			const struct gossmap_chan *chan,
			int dir)
{
	struct amount_msat msat;
	gossmap_chan_get_update_details(gossmap, chan, dir,
					NULL, NULL, NULL, NULL, NULL, &msat, NULL);
	return msat.millisatoshis; /* Raw: compressed format */
}

static u64 get_htlc_max(struct gossmap *gossmap,
			const struct gossmap_chan *chan,
			int dir)
{
	struct amount_msat msat, capacity_msat;
	struct amount_sat capacity_sats;
	gossmap_chan_get_capacity(gossmap, chan, &capacity_sats);
	gossmap_chan_get_update_details(gossmap, chan, dir,
					NULL, NULL, NULL, NULL, NULL, NULL, &msat);

	/* Special value for the common case of "max_htlc == capacity" */
	if (amount_msat_eq_sat(msat, capacity_sats)) {
		return 0;
	}
	/* Other common case: "max_htlc == 99% capacity" */
	if (amount_sat_to_msat(&capacity_msat, capacity_sats)
	    && amount_msat_scale(&capacity_msat, capacity_msat, 0.99)
	    && amount_msat_eq(msat, capacity_msat)) {
		return 1;
	}
	return msat.millisatoshis; /* Raw: compressed format */
}

static u64 get_basefee(struct gossmap *gossmap,
		       const struct gossmap_chan *chan,
		       int dir)
{
	u32 basefee;
	gossmap_chan_get_update_details(gossmap, chan, dir,
					NULL, NULL, NULL, &basefee, NULL, NULL, NULL);
	return basefee;
}

static u64 get_propfee(struct gossmap *gossmap,
		       const struct gossmap_chan *chan,
		       int dir)
{
	u32 propfee;
	gossmap_chan_get_update_details(gossmap, chan, dir,
					NULL, NULL, NULL, NULL, &propfee, NULL, NULL);
	return propfee;
}

static u64 get_delay(struct gossmap *gossmap,
		     const struct gossmap_chan *chan,
		     int dir)
{
	return chan->half[dir].delay;
}

int main(int argc, char *argv[])
{
	int infd, outfd;
	common_setup(argv[0]);
	setup_locale();

	opt_register_noarg("--verbose|-v", opt_set_bool, &verbose,
			   "Print details.");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "[decompress|compress] infile outfile"
			   "Compress or decompress a gossmap file",
			   "Print this message.");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 4)
		opt_usage_and_exit("Needs 4 arguments");

	infd = open(argv[2], O_RDONLY);
	if (infd < 0)
		opt_usage_and_exit(tal_fmt(tmpctx, "Cannot open %s for reading: %s",
					   argv[2], strerror(errno)));
	outfd = open(argv[3], O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (outfd < 0)
		opt_usage_and_exit(tal_fmt(tmpctx, "Cannot open %s for writing: %s",
					   argv[3], strerror(errno)));

	if (streq(argv[1], "compress")) {
		struct gossmap_node **nodes, *n;
		size_t *node_to_compr_idx;
		size_t node_count, channel_count;
		struct gossmap_chan **chans, *c;

		struct gossmap *gossmap = gossmap_load_fd(tmpctx, infd, NULL, NULL, NULL);
		if (!gossmap)
			opt_usage_and_exit("Cannot read gossmap");

		nodes = tal_arr(gossmap, struct gossmap_node *, gossmap_max_node_idx(gossmap));
		for (node_count = 0, n = gossmap_first_node(gossmap);
		     n;
		     n = gossmap_next_node(gossmap, n), node_count++) {
			nodes[node_count] = n;
		}
		tal_resize(&nodes, node_count);
		if (verbose)
			printf("%zu nodes\n", node_count);

		/* nodes with most channels go first */
		asort(nodes, tal_count(nodes), cmp_node_num_chans, NULL);

		/* Create map of gossmap index to compression index */
		node_to_compr_idx = tal_arr(nodes, size_t, gossmap_max_node_idx(gossmap));
		for (size_t i = 0; i < tal_count(nodes); i++)
			node_to_compr_idx[gossmap_node_idx(gossmap, nodes[i])] = i;

		if (!write_all(outfd, GC_HEADER, GC_HEADERLEN))
			err(1, "Writing header");

		/* Now, output channels.  First get exact count. */
		for (channel_count = 0, c = gossmap_first_chan(gossmap);
		     c;
		     c = gossmap_next_chan(gossmap, c)) {
			channel_count++;
		}

		if (verbose)
			printf("%zu channels\n", channel_count);
		chans = tal_arr(gossmap, struct gossmap_chan *, channel_count);

		/*  * <CHANNEL_ENDS> := {channel_count} {start_nodeidx}*{channel_count} {end_nodeidx}*{channel_count} */
		write_bigsize(outfd, channel_count);
		size_t chanidx = 0;
		/* We iterate nodes to get to channels.  This gives us nicer ordering for compression */
		for (size_t wanted_dir = 0; wanted_dir < 2; wanted_dir++) {
			for (n = gossmap_first_node(gossmap); n; n = gossmap_next_node(gossmap, n)) {
				for (size_t i = 0; i < n->num_chans; i++) {
					int dir;
					c = gossmap_nth_chan(gossmap, n, i, &dir);
					if (dir != wanted_dir)
						continue;

					write_bigsize(outfd,
						      node_to_compr_idx[gossmap_node_idx(gossmap, n)]);
					/* First time reflects channel index for reader */
					if (wanted_dir == 0)
						chans[chanidx++] = c;
				}
			}
		}

		/* <DISABLEDS> := <DISABLED>* {channel_count*2} */
		/* <DISABLED> := {chanidx}*2+{direction} */
		size_t num_disabled = 0;
		size_t num_unknown = 0;
		for (size_t i = 0; i < channel_count; i++) {
			for (size_t dir = 0; dir < 2; dir++) {
				if (chans[i]->cupdate_off[dir] == 0)
					num_unknown++;
				if (!chans[i]->half[dir].enabled) {
					write_bigsize(outfd, i * 2 + dir);
					num_disabled++;
				}
			}
		}
		write_bigsize(outfd, channel_count * 2);
		if (verbose)
			printf("%zu disabled channels (%zu no update)\n", num_disabled, num_unknown);

		/* <CAPACITIES> := <CAPACITY_TEMPLATES> {channel_count}*{capacity_idx} */
		/* <CAPACITY_TEMPLATES> := {capacity_count} {capacity_count}*{capacity} */
		u64 *vals = tal_arr(chans, u64, channel_count);
		for (size_t i = 0; i < channel_count; i++) {
			struct amount_sat sats;
			gossmap_chan_get_capacity(gossmap, chans[i], &sats);
			vals[i] = sats.satoshis; /* Raw: compression format */
		}
		write_template_and_values(outfd, vals, "capacities");

		/* These are all of same form: one entry per direction per channel */
		/* <HTLC_MINS> := <HTLC_MIN_TEMPLATES> {channel_count}*{htlc_min_idx} */
		/* <HTLC_MIN_TEMPLATES> := {htlc_min_count} {htlc_min_count}*{htlc_min} */
		/* <HTLC_MAXS> := <HTLC_MAX_TEMPLATES> {channel_count}*{htlc_max_idx} */
		/* <HTLC_MAX_TEMPLATES> := {htlc_max_count} {htlc_max_count}*{htlc_max} */
		/* <BASEFEES> := <BASEFEE_TEMPLATES> {channel_count}*{basefee_idx} */
		/* <BASEFEE_TEMPLATES> := {basefee_count} {basefee_count}*{basefee} */
		/* <PROPFEES> := <PROPFEE_TEMPLATES> {channel_count}*{propfee_idx} */
		/* <PROPFEE_TEMPLATES> := {propfee_count} {propfee_count}*{propfee} */
		/* <DELAYS> := <DELAY_TEMPLATES> {channel_count}*{delay_idx} */
		/* <DELAY_TEMPLATES> := {delay_count} {delay_count}*{delay} */
		write_bidir_perchan(outfd, gossmap, chans, get_htlc_min, "htlc_min");
		write_bidir_perchan(outfd, gossmap, chans, get_htlc_max, "htlc_max");
		write_bidir_perchan(outfd, gossmap, chans, get_basefee, "basefee");
		write_bidir_perchan(outfd, gossmap, chans, get_propfee, "propfee");
		write_bidir_perchan(outfd, gossmap, chans, get_delay, "delay");
	} else if (streq(argv[1], "decompress")) {
		errx(1, "NYI");
	} else
		opt_usage_and_exit("Unknown command");

	common_shutdown();
}
