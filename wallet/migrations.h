#ifndef LIGHTNING_WALLET_MIGRATIONS_H
#define LIGHTNING_WALLET_MIGRATIONS_H

#include "config.h"

struct lightningd;

struct db_migration {
	const char *sql;
	void (*func)(struct lightningd *ld, struct db *db);
	const char *revertsql;
	/* If non-NULL, returns string explaining why downgrade is impossible */
	const char *(*revertfn)(const tal_t *ctx, struct db *db);
};

const struct db_migration *get_db_migrations(size_t *num);

/* All the functions provided by migrations.c */
void migrate_pr2342_feerate_per_channel(struct lightningd *ld, struct db *db);
void migrate_our_funding(struct lightningd *ld, struct db *db);
void migrate_last_tx_to_psbt(struct lightningd *ld, struct db *db);
void migrate_inflight_last_tx_to_psbt(struct lightningd *ld, struct db *db);
void fillin_missing_scriptpubkeys(struct lightningd *ld, struct db *db);
void fillin_missing_channel_id(struct lightningd *ld, struct db *db);
void fillin_missing_local_basepoints(struct lightningd *ld,
				     struct db *db);
void fillin_missing_channel_blockheights(struct lightningd *ld,
					 struct db *db);
void migrate_channels_scids_as_integers(struct lightningd *ld,
					struct db *db);
void migrate_payments_scids_as_integers(struct lightningd *ld,
					struct db *db);
void fillin_missing_lease_satoshi(struct lightningd *ld,
				  struct db *db);
void migrate_invalid_last_tx_psbts(struct lightningd *ld,
				   struct db *db);
void migrate_fill_in_channel_type(struct lightningd *ld,
				  struct db *db);
void migrate_normalize_invstr(struct lightningd *ld,
			      struct db *db);
void migrate_initialize_invoice_wait_indexes(struct lightningd *ld,
					     struct db *db);
void migrate_invoice_created_index_var(struct lightningd *ld,
				       struct db *db);
void migrate_initialize_payment_wait_indexes(struct lightningd *ld,
					     struct db *db);
void migrate_forwards_add_rowid(struct lightningd *ld,
				struct db *db);
void migrate_initialize_forwards_wait_indexes(struct lightningd *ld,
					      struct db *db);
void migrate_initialize_alias_local(struct lightningd *ld,
				    struct db *db);
void insert_addrtype_to_addresses(struct lightningd *ld,
				  struct db *db);
void migrate_convert_old_channel_keyidx(struct lightningd *ld,
					struct db *db);
void migrate_initialize_channel_htlcs_wait_indexes_and_fixup_forwards(struct lightningd *ld,
								      struct db *db);
void migrate_fail_pending_payments_without_htlcs(struct lightningd *ld,
						 struct db *db);
void migrate_remove_chain_moves_duplicates(struct lightningd *ld, struct db *db);
void migrate_from_account_db(struct lightningd *ld, struct db *db);
void migrate_datastore_commando_runes(struct lightningd *ld, struct db *db);
void migrate_runes_idfix(struct lightningd *ld, struct db *db);
#endif /* LIGHTNING_WALLET_MIGRATIONS_H */
