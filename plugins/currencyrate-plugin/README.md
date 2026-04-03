# cln-currencyrate plugin

A Core Lightning plugin that provides Bitcoin currency conversion using multiple price sources. It queries all configured sources in parallel, caches results for one hour, and returns the median rate for conversions.

## Options

These options can be set in your `lightning.conf` config file or passed directly when starting the plugin.

### `currencyrate-add-source=NAME,URL,MEMBERS`

Add a custom price source. The format is `NAME,URL,MEMBERS` where:

- `NAME` — a unique identifier for the source
- `URL` — the API endpoint; use `{currency}` and `{currency_lc}` as placeholders for the plain currency (i.e. dollar, euro, etc.) and currency code respectively
- `MEMBERS` — comma-separated keys to traverse the JSON response to reach the price value; use `{currency}` and `{currency_lc}` as placeholders where needed

For example, if the API response is `{"rates": {"usd": 95000.0}}`, the `lightning.conf` entry would be:

```
currencyrate-add-source=currencyrateapi,https://currencyrateapi.com/api/latest?base=BTC&codes={currency_lc},rates,{currency_lc}
```

Can be specified multiple times to add multiple sources.

### `currencyrate-disable-source=NAME`

Disable a source by name (including default ones). Can be specified multiple times.

For example, to disable bitstamp:

```
currencyrate-disable-source=bitstamp
```

## Default Sources

| Source | Notes |
|---|---|
| coingecko | "The world's most comprehensive cryptocurrency API" |
| kraken | |
| blockchain.info | "The World's Most Popular Way to Buy, Hold, and Use Crypto" |
| bitstamp | "The original global crypto exchange." — disabled when a Tor proxy is configured |
| coindesk | "Powered by CoinDesk: https://www.coindesk.com/price/bitcoin" |
| coinbase | "The easiest place to buy, sell, and manage your cryptocurrency portfolio." |

## Configuring Sources Without Restarting the Node

Because the plugin is dynamic, you can stop and restart it with updated options without restarting `lightningd`. This lets you add or disable sources on the fly.

> **Warning:** while the plugin is stopped, any events that require a currency rate (e.g. invoice creation with a fiat amount) will fail or return missing data.

**1. Stop the plugin:**

```bash
lightning-cli plugin stop cln-currencyrate
```

**2.a Restart it with a new source:**

```bash
lightning-cli plugin -k subcommand=start \
  plugin=/path/to/cln-currencyrate \
  currencyrate-add-source="currencyrateapi,https://currencyrateapi.com/api/latest?base=BTC&codes={currency_lc},rates,{currency_lc}"
```

**2.b Restart it with a source disabled:**

```bash
lightning-cli plugin -k subcommand=start \
  plugin=/path/to/cln-currencyrate \
  currencyrate-disable-source="bitstamp"
```

For persistent configuration, add the options to your `lightning.conf` instead.
