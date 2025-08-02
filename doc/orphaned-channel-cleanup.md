# Orphaned Channel Cleanup Process

## Overview
Channels can become "orphaned" when they get stuck in the `CHANNELD_AWAITING_LOCKIN` state with a funding transaction that never confirms. This can happen if:
- The funding transaction was never broadcast
- The funding transaction was dropped from the mempool
- The transaction fee was too low and it got purged

## Detection Commands

### listorphanedchannels
Lists channels in `CHANNELD_AWAITING_LOCKIN` state where the funding transaction is not in the mempool.

```bash
lightning-cli listorphanedchannels [timeout_hours=48]
```

Parameters:
- `timeout_hours` (optional): Only show channels stuck for at least this many hours (default: 48)

Returns:
- Array of orphaned channels with details including peer_id, channel_id, funding_txid, hours_stuck
- Total count of orphaned channels

### cleanuporphanedchannels
Safely removes orphaned channels that have been stuck for the specified time.

```bash
lightning-cli cleanuporphanedchannels [timeout_hours=48] [force=false]
```

Parameters:
- `timeout_hours` (optional): Only cleanup channels stuck for at least this many hours (default: 48)
- `force` (optional): Force cleanup even if safety checks fail (default: false)

Safety checks:
- Channel must not have any pending HTLCs
- Channel must be in `CHANNELD_AWAITING_LOCKIN` state

## Manual Cleanup Process

1. First, identify orphaned channels:
   ```bash
   lightning-cli listorphanedchannels
   ```

2. Review each orphaned channel carefully:
   - Check the funding transaction status on a block explorer
   - Verify no funds are at risk

3. Clean up individual channels using dev-forget-channel:
   ```bash
   lightning-cli dev-forget-channel <peer_id> [short_channel_id] [force=true]
   ```

4. Or clean up all orphaned channels at once:
   ```bash
   lightning-cli cleanuporphanedchannels
   ```

## Monitoring

The node will log warnings when orphaned channels are detected:
```
UNUSUAL: Orphaned channel detected: funding_txid=xxx, outnum=0, stuck for 72 hours
```

## Prevention

To prevent orphaned channels:
1. Ensure funding transactions use appropriate fees
2. Monitor channel states after funding
3. Set up alerts for channels stuck in `CHANNELD_AWAITING_LOCKIN`
4. Consider implementing automatic cleanup policies

## Recovery

If you accidentally cleanup a channel with a valid funding transaction:
1. The funds remain safe in the funding output
2. You can spend the funding output using the commitment transaction
3. Contact support if you need assistance recovering funds