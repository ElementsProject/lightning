use anyhow::anyhow;
use futures::future::join_all;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::{Client, Proxy};
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::SourceResult;

const SOURCE_TIMEOUT_SECS: Duration = Duration::from_secs(10);
const SERVE_TTL: Duration = Duration::from_secs(3_600);
const DRIFT_THRESHOLD: f64 = 0.01;

const INITIAL_BACKOFF: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(3_600);

#[derive(Debug, Clone)]
pub struct Source {
    name: String,
    url_template: String,
    reply_members: Vec<String>,
}
impl PartialEq for Source {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
impl Source {
    pub fn new(name: &str, url_template: &str, reply_members: Vec<&str>) -> Self {
        Source {
            name: name.to_owned(),
            url_template: url_template.to_owned(),
            reply_members: reply_members
                .into_iter()
                .map(std::borrow::ToOwned::to_owned)
                .collect(),
        }
    }
    pub fn url(&self, currency_lc: &str, currency: &str) -> String {
        self.url_template
            .replace("{currency_lc}", currency_lc)
            .replace("{currency}", currency)
    }

    pub fn reply_members(&self, currency_lc: &str, currency: &str) -> Vec<String> {
        self.reply_members
            .iter()
            .map(|s| {
                s.replace("{currency_lc}", currency_lc)
                    .replace("{currency}", currency)
            })
            .collect()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    async fn get_rate(&self, client: &Client, currency: &str) -> Result<f64, anyhow::Error> {
        let now = Instant::now();

        let currency_lc = currency.to_lowercase();
        let currency = currency.to_uppercase();
        let url = self.url(&currency_lc, &currency);

        let resp: Value = client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to request url {url} caused by: {:?}", e.source()))?
            .json()
            .await
            .map_err(|e| {
                anyhow!(
                    "Failed to decode response body from {url}, caused by: {:?}",
                    e.source()
                )
            })?;

        let reply_members = self.reply_members(&currency_lc, &currency);

        let mut current = &mut resp.clone();
        for member in reply_members {
            if let Ok(pos) = member.parse::<usize>() {
                current = current.get_mut(pos).ok_or(anyhow!(
                    "Positional member `{}` not found in {} response: {}",
                    member,
                    self.name(),
                    resp
                ))?;
            } else {
                current = current.get_mut(&member).ok_or(anyhow!(
                    "Member `{}` not found in {} response: {}",
                    member,
                    self.name(),
                    resp
                ))?;
            }
        }
        let price = match current {
            Value::Number(number) => number
                .as_f64()
                .ok_or(anyhow!("Json number price could not be converted to float"))?,
            Value::String(string) => string
                .parse::<f64>()
                .map_err(|e| anyhow!("Price string could not be converted to float: {e}"))?,
            _ => return Err(anyhow!("Price is invalid json type")),
        };

        if price == 0.0 {
            log::warn!("{} returned 0.0 as price for {}", self.name, currency);
            return Err(anyhow!(
                "{} returned 0.0 as price for {}",
                self.name,
                currency
            ));
        }

        log::info!(
            "Fetched price in {}ms from {}: {:.2} {currency}",
            now.elapsed().as_millis(),
            self.name,
            price
        );

        Ok(1E11 / price)
    }
}

struct SourceHealth {
    source: Source,
    failures: u32,
    backoff_until: Instant,
}

impl SourceHealth {
    fn new(source: Source) -> Self {
        Self {
            source,
            failures: 0,
            backoff_until: Instant::now(),
        }
    }

    fn mark_success(&mut self) {
        self.failures = 0;
        self.backoff_until = Instant::now();
    }

    fn mark_failure(&mut self) {
        self.failures += 1;
        let delay = INITIAL_BACKOFF * 2u32.pow(self.failures.min(10));
        self.backoff_until = Instant::now() + delay.min(MAX_BACKOFF);
    }
}

#[derive(Debug)]
struct PriceCache {
    price: f64,
    timestamp: Instant,
}
struct CurrencyCache {
    prices: HashMap<String, PriceCache>,
    last_request: Instant,
}

impl CurrencyCache {
    fn new() -> Self {
        Self {
            prices: HashMap::new(),
            last_request: Instant::now(),
        }
    }

    fn latest_fresh_price(&self) -> Option<SourceResult> {
        self.prices
            .iter()
            .filter(|(_, p)| p.timestamp + SERVE_TTL > Instant::now())
            .max_by_key(|(_, p)| p.timestamp)
            .map(|(n, p)| SourceResult {
                name: n.clone(),
                price: p.price,
            })
    }

    fn is_drift_ok(&self) -> bool {
        let mut cache_sorted_by_recency: Vec<(&String, &PriceCache)> = self.prices.iter().collect();
        cache_sorted_by_recency.sort_by_key(|(_, p)| Reverse(p.timestamp));
        if cache_sorted_by_recency.len() == 1 {
            return true;
        }

        let latest_price = cache_sorted_by_recency.first().unwrap().1;
        let second_latest_price = cache_sorted_by_recency.get(1).unwrap().1;

        let relative_drift =
            f64::abs((latest_price.price - second_latest_price.price) / second_latest_price.price);

        if relative_drift > DRIFT_THRESHOLD {
            return false;
        }

        true
    }

    fn currency_requested(&mut self) {
        self.last_request = Instant::now();
    }

    fn is_currency_still_desired(&self) -> bool {
        self.last_request + SERVE_TTL * 3 > Instant::now()
    }
}

struct OracleInner {
    sources: HashMap<String, SourceHealth>,
    currencies: HashMap<String, CurrencyCache>,
}

impl OracleInner {
    fn reset_backoff_if_needed(&mut self, now: Instant) {
        // if all sources are backed off, reset them all to avoid indefinite starvation
        if self.sources.values().all(|sh| sh.backoff_until >= now) {
            for sh in self.sources.values_mut() {
                sh.mark_success();
            }
        }
    }
}

pub struct BtcPriceOracle {
    inner: Arc<Mutex<OracleInner>>,
    client: Client,
}

impl BtcPriceOracle {
    pub fn new(tor_proxy: Option<SocketAddr>, sources: Vec<Source>) -> Result<Self, anyhow::Error> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("cln-currencyrate"));

        let mut client = Client::builder()
            .default_headers(headers)
            .tls_backend_rustls()
            .timeout(SOURCE_TIMEOUT_SECS)
            .pool_max_idle_per_host(5);

        if let Some(tp) = tor_proxy {
            let proxy_url = format!("socks5h://{tp}");
            let proxy = Proxy::all(&proxy_url)?;

            client = client.proxy(proxy);
        }

        let client = client.build()?;

        let mut map = HashMap::new();
        for s in sources {
            map.insert(s.name().to_owned(), SourceHealth::new(s));
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(OracleInner {
                sources: map,
                currencies: HashMap::new(),
            })),
            client,
        })
    }

    pub async fn currency_requested(&self, currency: &str) {
        let mut inner = self.inner.lock().await;
        if let Some(cache) = inner.currencies.get_mut(currency) {
            cache.currency_requested();
        }
    }

    pub async fn get_all_rates(&self, currency: &str) -> Result<Vec<SourceResult>, anyhow::Error> {
        self.refresh_currency(currency).await?;

        let results = {
            let mut inner = self.inner.lock().await;
            let cache = inner
                .currencies
                .entry(currency.to_owned())
                .or_insert_with(CurrencyCache::new);

            cache
                .prices
                .iter()
                .filter(|(_, price_cache)| price_cache.timestamp + SERVE_TTL > Instant::now())
                .map(|(name, price)| SourceResult {
                    name: name.clone(),
                    price: price.price,
                })
                .collect::<Vec<_>>()
        };

        if results.is_empty() {
            return Err(anyhow::anyhow!(
                "no results for `{currency}`, is the currency supported? Check the logs!"
            ));
        }

        Ok(results)
    }

    pub async fn convert(&self, amount: f64, currency: &str) -> Result<u64, anyhow::Error> {
        let inner = self.inner.lock().await;
        let source_results = if let Some(currency_cache) = inner.currencies.get(currency) {
            if let Some(price) = currency_cache.latest_fresh_price() {
                vec![price]
            } else {
                log::warn!("background task failed to keep currency `{currency}` up to date");
                drop(inner);
                self.get_all_rates(currency).await?
            }
        } else {
            drop(inner);
            self.get_all_rates(currency).await?
        };

        let median_rate = get_median_rate(source_results);
        Ok((amount * median_rate).round() as u64)
    }

    async fn refresh_currency(&self, currency: &str) -> Result<(), anyhow::Error> {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let mut start_background_refresh = false;

        let mut source_candidates: Vec<String> = inner
            .sources
            .iter()
            .filter(|(_, s)| now >= s.backoff_until)
            .map(|(name, _)| name.clone())
            .collect();

        if source_candidates.is_empty() {
            log::warn!("all sources have failed recently, trying them immediately again");
            source_candidates = inner.sources.keys().cloned().collect();
        }

        let currency_cache = if let Some(c) = inner.currencies.get(currency) {
            c
        } else {
            inner
                .currencies
                .insert(currency.to_owned(), CurrencyCache::new());
            start_background_refresh = true;
            inner.currencies.get(currency).unwrap()
        };
        source_candidates.retain(|c| {
            currency_cache
                .prices
                .get(c)
                .is_none_or(|p| p.timestamp + SERVE_TTL <= now)
        });

        drop(inner);

        let futures = source_candidates.iter().map(|source_name| {
            let inner = self.inner.clone();
            let client = self.client.clone();
            let source_name = source_name.clone();

            async move {
                let source = {
                    let inner = inner.lock().await;
                    inner.sources.get(&source_name).unwrap().source.clone()
                };

                let rate_result = source.get_rate(&client, currency).await;

                let mut inner = inner.lock().await;

                let source_health = inner.sources.get_mut(&source_name).unwrap();

                match rate_result {
                    Ok(price) => {
                        source_health.mark_success();

                        let cache = inner.currencies.get_mut(currency).unwrap();
                        cache.prices.insert(
                            source_name,
                            PriceCache {
                                price,
                                timestamp: Instant::now(),
                            },
                        );
                    }

                    Err(e) => {
                        log::warn!("failed to get `{currency}` rate from {source_name}: {e}");
                        source_health.mark_failure();
                    }
                }
            }
        });

        join_all(futures).await;

        let had_any_success =
            if let Some(currency_cache) = self.inner.lock().await.currencies.get(currency) {
                !currency_cache.prices.is_empty()
            } else {
                false
            };

        if had_any_success && start_background_refresh {
            self.background_refresh(currency);
        }

        Ok(())
    }

    fn background_refresh(&self, currency: &str) {
        let inner = self.inner.clone();
        let client = self.client.clone();
        let currency = currency.to_owned();
        tokio::spawn(async move {
            tokio::time::sleep(SOURCE_TIMEOUT_SECS * 5).await;
            loop {
                let mut inner = inner.lock().await;
                let now = Instant::now();
                inner.reset_backoff_if_needed(now);
                let available_sources: Vec<String> = inner
                    .sources
                    .iter()
                    .filter(|(_, source_health)| source_health.backoff_until < now)
                    .map(|(name, _)| name)
                    .cloned()
                    .collect();

                let prices = inner
                    .currencies
                    .get(&currency)
                    .map(|currency_cache| &currency_cache.prices);

                let mut sources_by_staleness: Vec<(String, Option<Instant>)> = available_sources
                    .into_iter()
                    .map(|name| {
                        let last_fetch = prices
                            .and_then(|prices| prices.get(&name))
                            .map(|price_cache| price_cache.timestamp);
                        (name, last_fetch)
                    })
                    .collect();

                sources_by_staleness.sort_by_key(|(_, s)| *s);

                let stale_cutoff = now - SERVE_TTL + 2 * SOURCE_TIMEOUT_SECS;
                if sources_by_staleness
                    .last()
                    .and_then(|(_, timestamp)| *timestamp)
                    .is_some_and(|timestamp| timestamp > stale_cutoff)
                {
                    sources_by_staleness.clear();
                }

                log::trace!(
                    "sources_by_staleness: {}",
                    sources_by_staleness
                        .iter()
                        .map(|(n, p)| format!(
                            "{n}:{}",
                            p.map(|f| f.elapsed().as_secs()).unwrap_or(0)
                        ))
                        .collect::<Vec<String>>()
                        .join(", ")
                );

                for (name, _) in sources_by_staleness {
                    let source_health = inner.sources.get_mut(&name).unwrap();
                    match source_health.source.get_rate(&client, &currency).await {
                        Ok(price) => {
                            source_health.mark_success();

                            let currency_cache = inner.currencies.get_mut(&currency).unwrap();
                            currency_cache.prices.insert(
                                name.clone(),
                                PriceCache {
                                    price,
                                    timestamp: Instant::now(),
                                },
                            );

                            if currency_cache.is_drift_ok() {
                                break;
                            }
                        }
                        Err(e) => {
                            log::warn!("failed to get `{currency}` rate from {name}: {e}");
                            source_health.mark_failure();
                        }
                    }
                }

                if !inner
                    .currencies
                    .get(&currency)
                    .is_some_and(CurrencyCache::is_currency_still_desired)
                {
                    log::trace!("stopping background refresh for `{currency}`");
                    inner.currencies.remove(&currency);
                    break;
                }

                drop(inner);

                let interval = SERVE_TTL
                    .saturating_sub(2 * SOURCE_TIMEOUT_SECS)
                    .max(Duration::from_secs(1));

                tokio::time::sleep(interval).await;
            }
        });
    }
}

fn get_median_rate(source_results: Vec<SourceResult>) -> f64 {
    let mut prices: Vec<f64> = source_results.iter().map(|r| r.price).collect();
    prices.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = prices.len() / 2;
    if prices.len() % 2 == 1 {
        prices[mid]
    } else {
        f64::midpoint(prices[mid - 1], prices[mid])
    }
}
