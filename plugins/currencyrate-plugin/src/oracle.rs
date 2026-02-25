use anyhow::anyhow;
use futures::future::join_all;
use rand::seq::IndexedRandom;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::{Client, Proxy};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{CachedPrice, SourceResult, CONVERT_SOURCES_COUNT, SOURCE_TIMEOUT_SECS};

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

        log::debug!(
            "Fetched price in {}ms from {}: {:.2} {currency}",
            now.elapsed().as_millis(),
            self.name,
            price
        );

        Ok(1E11 / price)
    }
}

pub struct BtcPriceOracle {
    sources: Vec<Source>,
    cache: Option<CachedPrice>,
    cache_duration_s: u64,
    client: Client,
}

impl BtcPriceOracle {
    pub fn new(
        cache_duration_s: u64,
        tor_proxy: Option<SocketAddr>,
        sources: Vec<Source>,
    ) -> Result<Self, anyhow::Error> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("currencyrate-plugin"));

        let mut client = Client::builder()
            .default_headers(headers)
            .tls_backend_rustls()
            .timeout(Duration::from_secs(SOURCE_TIMEOUT_SECS))
            .pool_max_idle_per_host(5);

        if let Some(tp) = tor_proxy {
            let proxy_url = format!("socks5h://{tp}");
            let proxy = Proxy::all(&proxy_url)?;

            client = client.proxy(proxy);
        }

        let client = client.build()?;

        Ok(Self {
            sources,
            cache: None,
            cache_duration_s,
            client,
        })
    }

    pub async fn get_rates(
        &mut self,
        currency: &str,
        num_sources: usize,
    ) -> Result<Vec<SourceResult>, anyhow::Error> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        if let Some(cache) = &self.cache {
            if now - cache.timestamp < self.cache_duration_s {
                if let Some(price) = cache.data.get(currency) {
                    log::debug!("Using cached rates for {currency}");
                    return Ok(price.clone());
                }
            }
        }

        let mut source_results = Vec::with_capacity(self.sources.len());

        let sources: Vec<&Source> = {
            let mut rng = &mut rand::rng();
            self.sources
                .choose_multiple(&mut rng, num_sources)
                .collect()
        };

        let futures = sources.iter().map(|source| {
            let client = &self.client;
            async move { (source.name(), source.get_rate(client, currency).await) }
        });

        let results = join_all(futures).await;

        for (name, result) in results {
            match result {
                Ok(price) => {
                    source_results.push(SourceResult {
                        price,
                        name: name.to_owned(),
                    });
                }
                Err(e) => {
                    log::warn!("Error fetching from {name}: {e}");
                }
            }
        }

        if source_results.len() < num_sources {
            let remaining_sources: Vec<&Source> = self
                .sources
                .iter()
                .filter(|s| !sources.contains(s))
                .collect();
            for source in remaining_sources {
                if source_results.len() >= num_sources {
                    break;
                }
                match source.get_rate(&self.client, currency).await {
                    Ok(price) => {
                        source_results.push(SourceResult {
                            price,
                            name: source.name().to_owned(),
                        });
                    }
                    Err(e) => {
                        log::warn!("Error fetching from {}: {e}", source.name);
                    }
                }
            }
        }

        if source_results.is_empty() {
            return Err(anyhow!(
                "No sources configured or all failed, check the logs."
            ));
        }

        source_results.sort_by(|a, b| a.price.partial_cmp(&b.price).unwrap());

        if let Some(cache) = &mut self.cache {
            cache
                .data
                .insert(currency.to_string(), source_results.clone());
            cache.timestamp = now;
        } else {
            let mut data = HashMap::new();
            data.insert(currency.to_string(), source_results.clone());
            self.cache = Some(CachedPrice {
                data,
                timestamp: now,
            });
        }
        Ok(source_results)
    }

    pub async fn convert(&mut self, amount: f64, currency: &str) -> Result<u64, anyhow::Error> {
        let source_results = self.get_rates(currency, CONVERT_SOURCES_COUNT).await?;
        let median_rate = get_median_rate(source_results);
        Ok((amount * median_rate).round() as u64)
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}

fn get_median_rate(source_results: Vec<SourceResult>) -> f64 {
    let mid = source_results.len() / 2;
    if source_results.len() % 2 == 1 {
        source_results[mid].price
    } else {
        f64::midpoint(source_results[mid - 1].price, source_results[mid].price)
    }
}
