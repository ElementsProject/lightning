lightning-sql -- Command to do complex queries on list commands
===============================================================

SYNOPSIS
--------

**sql** *query*

DESCRIPTION
-----------

The **sql** RPC command runs the given query across a sqlite3 database
created from various list commands.

When tables are accessed, it calls the above commands, so it's no
faster than any other local access (though it goes to great length to
cache `listnodes` and `listchannels`) which then processes the results.

It is, however faster for remote access if the result of the query is
much smaller than the list commands would be.

Note that queries like "SELECT *" are fragile, as columns will
change across releases; see lightning-listsqlschemas(7).

TREATMENT OF TYPES
------------------

The following types are supported in schemas, and this shows how they
are presented in the database. This matters: a JSON boolean is
represented as an integer in the database, so a query will return 0 or
1, not true or false.

* *hex*. A hex string.
  * JSON: a string
  * sqlite3: BLOB

* *hash*/*secret*/*pubkey*/*txid*: just like *hex*.

* *msat*/*integer*/*u64*/*u32*/*u16*/*u8*. Normal numbers.
  * JSON: an unsigned integer
  * sqlite3: INTEGER

* *boolean*. True or false.
  * JSON: literal **true** or **false**
  * sqlite3: INTEGER

* *number*. A floating point number (used for times in some places).
  * JSON: number
  * sqlite3: REAL

* *string*. Text.
  * JSON: string
  * sqlite3: TEXT

* *short\_channel\_id*. A short-channel-id of form 1x2x3.
  * JSON: string
  * sqlite3: TEXT

PERMITTED SQLITE3 FUNCTIONS
---------------------------

Writing to the database is not permitted, and limits are placed
on various other query parameters.

Additionally, only the following functions are allowed:

* abs
* avg
* coalesce
* count
* hex
* quote
* length
* like
* lower
* upper
* min
* max
* sum
* total

TABLES
------

Note that the first column of every table is a unique integer called
`rowid`: this is used for related tables to refer to specific rows in
their parent. sqlite3 usually has this as an implicit column, but we
make it explicit as the implicit version is not allowed to be used as
a foreign key.

[comment]: # (GENERATE-DOC-START)
The following tables are currently supported:
- `bkpr_accountevents` (see lightning-bkpr-listaccountevents(7))
  - `account` (type `string`, sqltype `TEXT`)
  - `type` (type `string`, sqltype `TEXT`)
  - `tag` (type `string`, sqltype `TEXT`)
  - `credit_msat` (type `msat`, sqltype `INTEGER`)
  - `debit_msat` (type `msat`, sqltype `INTEGER`)
  - `currency` (type `string`, sqltype `TEXT`)
  - `timestamp` (type `u32`, sqltype `INTEGER`)
  - `outpoint` (type `string`, sqltype `TEXT`)
  - `blockheight` (type `u32`, sqltype `INTEGER`)
  - `origin` (type `string`, sqltype `TEXT`)
  - `payment_id` (type `hex`, sqltype `BLOB`)
  - `txid` (type `txid`, sqltype `BLOB`)
  - `description` (type `string`, sqltype `TEXT`)
  - `fees_msat` (type `msat`, sqltype `INTEGER`)
  - `is_rebalance` (type `boolean`, sqltype `INTEGER`)
  - `part_id` (type `u32`, sqltype `INTEGER`)

- `bkpr_income` (see lightning-bkpr-listincome(7))
  - `account` (type `string`, sqltype `TEXT`)
  - `tag` (type `string`, sqltype `TEXT`)
  - `credit_msat` (type `msat`, sqltype `INTEGER`)
  - `debit_msat` (type `msat`, sqltype `INTEGER`)
  - `currency` (type `string`, sqltype `TEXT`)
  - `timestamp` (type `u32`, sqltype `INTEGER`)
  - `description` (type `string`, sqltype `TEXT`)
  - `outpoint` (type `string`, sqltype `TEXT`)
  - `txid` (type `txid`, sqltype `BLOB`)
  - `payment_id` (type `hex`, sqltype `BLOB`)

- `channels` indexed by `short_channel_id` (see lightning-listchannels(7))
  - `source` (type `pubkey`, sqltype `BLOB`)
  - `destination` (type `pubkey`, sqltype `BLOB`)
  - `short_channel_id` (type `short_channel_id`, sqltype `TEXT`)
  - `direction` (type `u32`, sqltype `INTEGER`)
  - `public` (type `boolean`, sqltype `INTEGER`)
  - `amount_msat` (type `msat`, sqltype `INTEGER`)
  - `message_flags` (type `u8`, sqltype `INTEGER`)
  - `channel_flags` (type `u8`, sqltype `INTEGER`)
  - `active` (type `boolean`, sqltype `INTEGER`)
  - `last_update` (type `u32`, sqltype `INTEGER`)
  - `base_fee_millisatoshi` (type `u32`, sqltype `INTEGER`)
  - `fee_per_millionth` (type `u32`, sqltype `INTEGER`)
  - `delay` (type `u32`, sqltype `INTEGER`)
  - `htlc_minimum_msat` (type `msat`, sqltype `INTEGER`)
  - `htlc_maximum_msat` (type `msat`, sqltype `INTEGER`)
  - `features` (type `hex`, sqltype `BLOB`)

- `closedchannels` (see lightning-listclosedchannels(7))
  - `peer_id` (type `pubkey`, sqltype `BLOB`)
  - `channel_id` (type `hash`, sqltype `BLOB`)
  - `short_channel_id` (type `short_channel_id`, sqltype `TEXT`)
  - `alias_local` (type `short_channel_id`, sqltype `TEXT`, from JSON object `alias`)
  - `alias_remote` (type `short_channel_id`, sqltype `TEXT`, from JSON object `alias`)
  - `opener` (type `string`, sqltype `TEXT`)
  - `closer` (type `string`, sqltype `TEXT`)
  - `private` (type `boolean`, sqltype `INTEGER`)
  - related table `closedchannels_channel_type_bits`, from JSON object `channel_type`
    - `row` (reference to `closedchannels_channel_type.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `bits` (type `u32`, sqltype `INTEGER`)
  - related table `closedchannels_channel_type_names`, from JSON object `channel_type`
    - `row` (reference to `closedchannels_channel_type.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `names` (type `string`, sqltype `TEXT`)
  - `total_local_commitments` (type `u64`, sqltype `INTEGER`)
  - `total_remote_commitments` (type `u64`, sqltype `INTEGER`)
  - `total_htlcs_sent` (type `u64`, sqltype `INTEGER`)
  - `funding_txid` (type `txid`, sqltype `BLOB`)
  - `funding_outnum` (type `u32`, sqltype `INTEGER`)
  - `leased` (type `boolean`, sqltype `INTEGER`)
  - `funding_fee_paid_msat` (type `msat`, sqltype `INTEGER`)
  - `funding_fee_rcvd_msat` (type `msat`, sqltype `INTEGER`)
  - `funding_pushed_msat` (type `msat`, sqltype `INTEGER`)
  - `total_msat` (type `msat`, sqltype `INTEGER`)
  - `final_to_us_msat` (type `msat`, sqltype `INTEGER`)
  - `min_to_us_msat` (type `msat`, sqltype `INTEGER`)
  - `max_to_us_msat` (type `msat`, sqltype `INTEGER`)
  - `last_commitment_txid` (type `hash`, sqltype `BLOB`)
  - `last_commitment_fee_msat` (type `msat`, sqltype `INTEGER`)
  - `close_cause` (type `string`, sqltype `TEXT`)
  - `last_stable_connection` (type `u64`, sqltype `INTEGER`)

- `forwards` indexed by `in_channel and in_htlc_id` (see lightning-listforwards(7))
  - `created_index` (type `u64`, sqltype `INTEGER`)
  - `in_channel` (type `short_channel_id`, sqltype `TEXT`)
  - `in_htlc_id` (type `u64`, sqltype `INTEGER`)
  - `in_msat` (type `msat`, sqltype `INTEGER`)
  - `status` (type `string`, sqltype `TEXT`)
  - `received_time` (type `number`, sqltype `REAL`)
  - `out_channel` (type `short_channel_id`, sqltype `TEXT`)
  - `out_htlc_id` (type `u64`, sqltype `INTEGER`)
  - `updated_index` (type `u64`, sqltype `INTEGER`)
  - `style` (type `string`, sqltype `TEXT`)
  - `fee_msat` (type `msat`, sqltype `INTEGER`)
  - `out_msat` (type `msat`, sqltype `INTEGER`)
  - `resolved_time` (type `number`, sqltype `REAL`)
  - `failcode` (type `u32`, sqltype `INTEGER`)
  - `failreason` (type `string`, sqltype `TEXT`)

- `htlcs` indexed by `short_channel_id and id` (see lightning-listhtlcs(7))
  - `short_channel_id` (type `short_channel_id`, sqltype `TEXT`)
  - `id` (type `u64`, sqltype `INTEGER`)
  - `expiry` (type `u32`, sqltype `INTEGER`)
  - `amount_msat` (type `msat`, sqltype `INTEGER`)
  - `direction` (type `string`, sqltype `TEXT`)
  - `payment_hash` (type `hash`, sqltype `BLOB`)
  - `state` (type `string`, sqltype `TEXT`)

- `invoices` indexed by `payment_hash` (see lightning-listinvoices(7))
  - `label` (type `string`, sqltype `TEXT`)
  - `description` (type `string`, sqltype `TEXT`)
  - `payment_hash` (type `hash`, sqltype `BLOB`)
  - `status` (type `string`, sqltype `TEXT`)
  - `expires_at` (type `u64`, sqltype `INTEGER`)
  - `amount_msat` (type `msat`, sqltype `INTEGER`)
  - `bolt11` (type `string`, sqltype `TEXT`)
  - `bolt12` (type `string`, sqltype `TEXT`)
  - `local_offer_id` (type `hash`, sqltype `BLOB`)
  - `invreq_payer_note` (type `string`, sqltype `TEXT`)
  - `created_index` (type `u64`, sqltype `INTEGER`)
  - `updated_index` (type `u64`, sqltype `INTEGER`)
  - `pay_index` (type `u64`, sqltype `INTEGER`)
  - `amount_received_msat` (type `msat`, sqltype `INTEGER`)
  - `paid_at` (type `u64`, sqltype `INTEGER`)
  - `paid_outpoint_txid` (type `txid`, sqltype `BLOB`, from JSON object `paid_outpoint`)
  - `paid_outpoint_outnum` (type `u32`, sqltype `INTEGER`, from JSON object `paid_outpoint`)
  - `payment_preimage` (type `secret`, sqltype `BLOB`)

- `nodes` indexed by `nodeid` (see lightning-listnodes(7))
  - `nodeid` (type `pubkey`, sqltype `BLOB`)
  - `last_timestamp` (type `u32`, sqltype `INTEGER`)
  - `alias` (type `string`, sqltype `TEXT`)
  - `color` (type `hex`, sqltype `BLOB`)
  - `features` (type `hex`, sqltype `BLOB`)
  - related table `nodes_addresses`
    - `row` (reference to `nodes.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `type` (type `string`, sqltype `TEXT`)
    - `port` (type `u16`, sqltype `INTEGER`)
    - `address` (type `string`, sqltype `TEXT`)
  - `option_will_fund_lease_fee_base_msat` (type `msat`, sqltype `INTEGER`, from JSON object `option_will_fund`)
  - `option_will_fund_lease_fee_basis` (type `u32`, sqltype `INTEGER`, from JSON object `option_will_fund`)
  - `option_will_fund_funding_weight` (type `u32`, sqltype `INTEGER`, from JSON object `option_will_fund`)
  - `option_will_fund_channel_fee_max_base_msat` (type `msat`, sqltype `INTEGER`, from JSON object `option_will_fund`)
  - `option_will_fund_channel_fee_max_proportional_thousandths` (type `u32`, sqltype `INTEGER`, from JSON object `option_will_fund`)
  - `option_will_fund_compact_lease` (type `hex`, sqltype `BLOB`, from JSON object `option_will_fund`)

- `offers` indexed by `offer_id` (see lightning-listoffers(7))
  - `offer_id` (type `hash`, sqltype `BLOB`)
  - `active` (type `boolean`, sqltype `INTEGER`)
  - `single_use` (type `boolean`, sqltype `INTEGER`)
  - `bolt12` (type `string`, sqltype `TEXT`)
  - `used` (type `boolean`, sqltype `INTEGER`)
  - `label` (type `string`, sqltype `TEXT`)

- `peerchannels` indexed by `peer_id` (see lightning-listpeerchannels(7))
  - `peer_id` (type `pubkey`, sqltype `BLOB`)
  - `peer_connected` (type `boolean`, sqltype `INTEGER`)
  - `reestablished` (type `boolean`, sqltype `INTEGER`)
  - `state` (type `string`, sqltype `TEXT`)
  - `scratch_txid` (type `txid`, sqltype `BLOB`)
  - related table `peerchannels_channel_type_bits`, from JSON object `channel_type`
    - `row` (reference to `peerchannels_channel_type.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `bits` (type `u32`, sqltype `INTEGER`)
  - related table `peerchannels_channel_type_names`, from JSON object `channel_type`
    - `row` (reference to `peerchannels_channel_type.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `names` (type `string`, sqltype `TEXT`)
  - `local_htlc_minimum_msat` (type `msat`, sqltype `INTEGER`, from JSON object `local`)
  - `local_htlc_maximum_msat` (type `msat`, sqltype `INTEGER`, from JSON object `local`)
  - `local_cltv_expiry_delta` (type `u32`, sqltype `INTEGER`, from JSON object `local`)
  - `local_fee_base_msat` (type `msat`, sqltype `INTEGER`, from JSON object `local`)
  - `local_fee_proportional_millionths` (type `u32`, sqltype `INTEGER`, from JSON object `local`)
  - `remote_htlc_minimum_msat` (type `msat`, sqltype `INTEGER`, from JSON object `remote`)
  - `remote_htlc_maximum_msat` (type `msat`, sqltype `INTEGER`, from JSON object `remote`)
  - `remote_cltv_expiry_delta` (type `u32`, sqltype `INTEGER`, from JSON object `remote`)
  - `remote_fee_base_msat` (type `msat`, sqltype `INTEGER`, from JSON object `remote`)
  - `remote_fee_proportional_millionths` (type `u32`, sqltype `INTEGER`, from JSON object `remote`)
  - `ignore_fee_limits` (type `boolean`, sqltype `INTEGER`)
  - `lost_state` (type `boolean`, sqltype `INTEGER`)
  - `feerate_perkw` (type `u32`, sqltype `INTEGER`, from JSON object `feerate`)
  - `feerate_perkb` (type `u32`, sqltype `INTEGER`, from JSON object `feerate`)
  - `owner` (type `string`, sqltype `TEXT`)
  - `short_channel_id` (type `short_channel_id`, sqltype `TEXT`)
  - `channel_id` (type `hash`, sqltype `BLOB`)
  - `funding_txid` (type `txid`, sqltype `BLOB`)
  - `funding_outnum` (type `u32`, sqltype `INTEGER`)
  - `initial_feerate` (type `string`, sqltype `TEXT`)
  - `last_feerate` (type `string`, sqltype `TEXT`)
  - `next_feerate` (type `string`, sqltype `TEXT`)
  - `next_fee_step` (type `u32`, sqltype `INTEGER`)
  - related table `peerchannels_inflight`
    - `row` (reference to `peerchannels.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `funding_txid` (type `txid`, sqltype `BLOB`)
    - `funding_outnum` (type `u32`, sqltype `INTEGER`)
    - `feerate` (type `string`, sqltype `TEXT`)
    - `total_funding_msat` (type `msat`, sqltype `INTEGER`)
    - `splice_amount` (type `integer`, sqltype `INTEGER`)
    - `our_funding_msat` (type `msat`, sqltype `INTEGER`)
    - `scratch_txid` (type `txid`, sqltype `BLOB`)
  - `close_to` (type `hex`, sqltype `BLOB`)
  - `private` (type `boolean`, sqltype `INTEGER`)
  - `opener` (type `string`, sqltype `TEXT`)
  - `closer` (type `string`, sqltype `TEXT`)
  - related table `peerchannels_features`
    - `row` (reference to `peerchannels.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `features` (type `string`, sqltype `TEXT`)
  - `funding_pushed_msat` (type `msat`, sqltype `INTEGER`, from JSON object `funding`)
  - `funding_local_funds_msat` (type `msat`, sqltype `INTEGER`, from JSON object `funding`)
  - `funding_remote_funds_msat` (type `msat`, sqltype `INTEGER`, from JSON object `funding`)
  - `funding_fee_paid_msat` (type `msat`, sqltype `INTEGER`, from JSON object `funding`)
  - `funding_fee_rcvd_msat` (type `msat`, sqltype `INTEGER`, from JSON object `funding`)
  - `to_us_msat` (type `msat`, sqltype `INTEGER`)
  - `min_to_us_msat` (type `msat`, sqltype `INTEGER`)
  - `max_to_us_msat` (type `msat`, sqltype `INTEGER`)
  - `total_msat` (type `msat`, sqltype `INTEGER`)
  - `fee_base_msat` (type `msat`, sqltype `INTEGER`)
  - `fee_proportional_millionths` (type `u32`, sqltype `INTEGER`)
  - `dust_limit_msat` (type `msat`, sqltype `INTEGER`)
  - `max_total_htlc_in_msat` (type `msat`, sqltype `INTEGER`)
  - `their_reserve_msat` (type `msat`, sqltype `INTEGER`)
  - `our_reserve_msat` (type `msat`, sqltype `INTEGER`)
  - `spendable_msat` (type `msat`, sqltype `INTEGER`)
  - `receivable_msat` (type `msat`, sqltype `INTEGER`)
  - `minimum_htlc_in_msat` (type `msat`, sqltype `INTEGER`)
  - `minimum_htlc_out_msat` (type `msat`, sqltype `INTEGER`)
  - `maximum_htlc_out_msat` (type `msat`, sqltype `INTEGER`)
  - `their_to_self_delay` (type `u32`, sqltype `INTEGER`)
  - `our_to_self_delay` (type `u32`, sqltype `INTEGER`)
  - `max_accepted_htlcs` (type `u32`, sqltype `INTEGER`)
  - `alias_local` (type `short_channel_id`, sqltype `TEXT`, from JSON object `alias`)
  - `alias_remote` (type `short_channel_id`, sqltype `TEXT`, from JSON object `alias`)
  - related table `peerchannels_state_changes`
    - `row` (reference to `peerchannels.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `timestamp` (type `string`, sqltype `TEXT`)
    - `old_state` (type `string`, sqltype `TEXT`)
    - `new_state` (type `string`, sqltype `TEXT`)
    - `cause` (type `string`, sqltype `TEXT`)
    - `message` (type `string`, sqltype `TEXT`)
  - related table `peerchannels_status`
    - `row` (reference to `peerchannels.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `status` (type `string`, sqltype `TEXT`)
  - `in_payments_offered` (type `u64`, sqltype `INTEGER`)
  - `in_offered_msat` (type `msat`, sqltype `INTEGER`)
  - `in_payments_fulfilled` (type `u64`, sqltype `INTEGER`)
  - `in_fulfilled_msat` (type `msat`, sqltype `INTEGER`)
  - `out_payments_offered` (type `u64`, sqltype `INTEGER`)
  - `out_offered_msat` (type `msat`, sqltype `INTEGER`)
  - `out_payments_fulfilled` (type `u64`, sqltype `INTEGER`)
  - `out_fulfilled_msat` (type `msat`, sqltype `INTEGER`)
  - `last_stable_connection` (type `u64`, sqltype `INTEGER`)
  - related table `peerchannels_htlcs`
    - `row` (reference to `peerchannels.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `direction` (type `string`, sqltype `TEXT`)
    - `id` (type `u64`, sqltype `INTEGER`)
    - `amount_msat` (type `msat`, sqltype `INTEGER`)
    - `expiry` (type `u32`, sqltype `INTEGER`)
    - `payment_hash` (type `hash`, sqltype `BLOB`)
    - `local_trimmed` (type `boolean`, sqltype `INTEGER`)
    - `status` (type `string`, sqltype `TEXT`)
    - `state` (type `string`, sqltype `TEXT`)
  - `close_to_addr` (type `string`, sqltype `TEXT`)
  - `last_tx_fee_msat` (type `msat`, sqltype `INTEGER`)
  - `direction` (type `u32`, sqltype `INTEGER`)

- `peers` indexed by `id` (see lightning-listpeers(7))
  - `id` (type `pubkey`, sqltype `BLOB`)
  - `connected` (type `boolean`, sqltype `INTEGER`)
  - `num_channels` (type `u32`, sqltype `INTEGER`)
  - related table `peers_netaddr`
    - `row` (reference to `peers.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `netaddr` (type `string`, sqltype `TEXT`)
  - `remote_addr` (type `string`, sqltype `TEXT`)
  - `features` (type `hex`, sqltype `BLOB`)

- `sendpays` indexed by `payment_hash` (see lightning-listsendpays(7))
  - `created_index` (type `u64`, sqltype `INTEGER`)
  - `id` (type `u64`, sqltype `INTEGER`)
  - `groupid` (type `u64`, sqltype `INTEGER`)
  - `partid` (type `u64`, sqltype `INTEGER`)
  - `payment_hash` (type `hash`, sqltype `BLOB`)
  - `updated_index` (type `u64`, sqltype `INTEGER`)
  - `status` (type `string`, sqltype `TEXT`)
  - `amount_msat` (type `msat`, sqltype `INTEGER`)
  - `destination` (type `pubkey`, sqltype `BLOB`)
  - `created_at` (type `u64`, sqltype `INTEGER`)
  - `amount_sent_msat` (type `msat`, sqltype `INTEGER`)
  - `label` (type `string`, sqltype `TEXT`)
  - `bolt11` (type `string`, sqltype `TEXT`)
  - `description` (type `string`, sqltype `TEXT`)
  - `bolt12` (type `string`, sqltype `TEXT`)
  - `completed_at` (type `u64`, sqltype `INTEGER`)
  - `payment_preimage` (type `secret`, sqltype `BLOB`)
  - `erroronion` (type `hex`, sqltype `BLOB`)

- `transactions` indexed by `hash` (see lightning-listtransactions(7))
  - `hash` (type `txid`, sqltype `BLOB`)
  - `rawtx` (type `hex`, sqltype `BLOB`)
  - `blockheight` (type `u32`, sqltype `INTEGER`)
  - `txindex` (type `u32`, sqltype `INTEGER`)
  - `locktime` (type `u32`, sqltype `INTEGER`)
  - `version` (type `u32`, sqltype `INTEGER`)
  - related table `transactions_inputs`
    - `row` (reference to `transactions.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `txid` (type `txid`, sqltype `BLOB`)
    - `idx` (type `u32`, sqltype `INTEGER`, from JSON field `index`)
    - `sequence` (type `u32`, sqltype `INTEGER`)
  - related table `transactions_outputs`
    - `row` (reference to `transactions.rowid`, sqltype `INTEGER`)
    - `arrindex` (index within array, sqltype `INTEGER`)
    - `idx` (type `u32`, sqltype `INTEGER`, from JSON field `index`)
    - `amount_msat` (type `msat`, sqltype `INTEGER`)
    - `scriptPubKey` (type `hex`, sqltype `BLOB`)

[comment]: # (GENERATE-DOC-END)

RETURN VALUE
------------

[comment]: # (FIXME: we don't handle this schema in fromschema.py)
On success, an object containing **rows** is returned.  It is an array. Each array entry contains an array of values, each an integer, real number, string or *null*, depending on the sqlite3 type.

The object may contain **warning\_db\_failure** if the database fails partway through its operation.

ERRORS
------

On failure, an error is returned.

EXAMPLE USAGE
-------------

Here are some example using lightning-cli. Note that you may need to
use `-o` if you use queries which contain `=` (which make
lightning-cli(1) default to keyword style):

A simple peer selection query:

```
$ lightning-cli sql "SELECT id FROM peers"
{
   "rows": [
      [
         "02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00"
      ]
   ]
}
```

A statement containing using `=` needs `-o`:

```
$ lightning-cli sql -o "SELECT node_id,last_timestamp FROM nodes WHERE last_timestamp>=1669578892"
{
   "rows": [
      [
         "02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00",
         1669601603
      ]
   ]
}
```

If you want to compare a BLOB column, `x'hex'` or `X'hex'` are needed:

```
$ lightning-cli sql -o "SELECT nodeid FROM nodes WHERE nodeid != x'03c9d25b6c0ce4bde5ad97d7ab83f00ae8bd3800a98ccbee36f3c3205315147de1';"
{
   "rows": [
      [
         "0214739d625944f8fdc0da9d2ef44dbd7af58443685e494117b51410c5c3ff973a"
      ],
      [
         "02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00"
      ]
   ]
}
$ lightning-cli sql -o "SELECT nodeid FROM nodes WHERE nodeid IN (x'03c9d25b6c0ce4bde5ad97d7ab83f00ae8bd3800a98ccbee36f3c3205315147de1', x'02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00')"
{
   "rows": [
      [
         "02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00"
      ],
      [
         "03c9d25b6c0ce4bde5ad97d7ab83f00ae8bd3800a98ccbee36f3c3205315147de1"
      ]
   ]
}
```

Related tables are usually referenced by JOIN:

```
$ lightning-cli sql -o "SELECT nodeid, alias, nodes_addresses.type, nodes_addresses.port, nodes_addresses.address FROM nodes INNER JOIN nodes_addresses ON nodes_addresses.row = nodes.rowid"
{
   "rows": [
      [
         "02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00",
         "YELLOWWATCH-22.11rc2-31-gcd7593b",
         "dns",
         7272,
         "localhost"
      ],
      [
         "0214739d625944f8fdc0da9d2ef44dbd7af58443685e494117b51410c5c3ff973a",
         "HOPPINGSQUIRREL-1rc2-31-gcd7593b",
         "dns",
         7171,
         "localhost"
      ]
   ]
}
```

Simple function usage, in this case COUNT. Strings inside arrays need
", and ' to protect them from the shell:

```
$ lightning-cli sql 'SELECT COUNT(*) FROM nodes"
{
   "rows": [
      [
         3
      ]
   ]
}
```

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listtransactions(7), lightning-listchannels(7), lightning-listpeers(7), lightning-listnodes(7), lightning-listforwards(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:5c2e41cab6704299c65a8537761f3864e6b3327c1bf9163b00afe723d1f84eb6)
