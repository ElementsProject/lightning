#include <lightningd/coin_mvts.h>
#include <lightningd/notification.h>

static s64 update_count(struct lightningd *ld)
{
	s64 count;
	count = ++ld->coin_moves_count;
	db_set_intvar(ld->wallet->db, "coin_moves_count", count);

	return count;
}

void notify_channel_mvt(struct lightningd *ld, const struct channel_coin_mvt *mvt)
{
	const struct coin_mvt *cm;
	u32 timestamp;
	s64 count;

	timestamp = time_now().ts.tv_sec;
	count = update_count(ld);
	cm = finalize_channel_mvt(mvt, mvt, timestamp,
				  &ld->id, count);
	notify_coin_mvt(ld, cm);
}

void notify_chain_mvt(struct lightningd *ld, const struct chain_coin_mvt *mvt)
{
	const struct coin_mvt *cm;
	u32 timestamp;
	s64 count;

	timestamp = time_now().ts.tv_sec;
	count = update_count(ld);
	cm = finalize_chain_mvt(mvt, mvt, timestamp,
				&ld->id, count);
	notify_coin_mvt(ld, cm);
}

void coin_mvts_init_count(struct lightningd *ld)
{
	s64 count;
	db_begin_transaction(ld->wallet->db);
	count = db_get_intvar(ld->wallet->db,
			      "coin_moves_count", -1);
	db_commit_transaction(ld->wallet->db);
	if (count == -1)
		fatal("Something went wrong attempting to fetch"
		      "the latest `coin_moves_count` from the intvars "
		      "table");
	ld->coin_moves_count = count;
}
