use crate::model::{Kind, Profile};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

pub const DEFAULT_PROBE_URL: &str = "http://cp.cloudflare.com/generate_204";
pub const MAX_ROLLING_SAMPLES: usize = 20;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SelectionMode {
    #[default]
    Manual,
    AutoBest,
    FallbackGroup,
    LoadBalanceGroup,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ScoringWeights {
    pub latency_weight: f64,
    pub jitter_weight: f64,
    pub loss_weight: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            latency_weight: 0.45,
            jitter_weight: 0.25,
            loss_weight: 0.30,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct NodeMetrics {
    pub rtt_history: VecDeque<Option<u32>>,
    pub last_probe_ts: Option<u64>,
    pub last_tcp_ms: Option<u32>,
    pub last_tls_ms: Option<u32>,
    pub last_real_delay_ms: Option<u32>,
    pub throughput_sample_kbps: Option<f64>,
}

impl NodeMetrics {
    pub fn new() -> Self {
        Self {
            rtt_history: VecDeque::with_capacity(MAX_ROLLING_SAMPLES),
            last_probe_ts: None,
            last_tcp_ms: None,
            last_tls_ms: None,
            last_real_delay_ms: None,
            throughput_sample_kbps: None,
        }
    }

    pub fn record_sample(&mut self, rtt: Option<u32>) {
        if self.rtt_history.len() >= MAX_ROLLING_SAMPLES {
            self.rtt_history.pop_front();
        }
        self.rtt_history.push_back(rtt);
        self.last_probe_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
    }

    /// Calculates median RTT from successful samples.
    pub fn median_rtt(&self) -> Option<u32> {
        let mut valid: Vec<u32> = self.rtt_history.iter().filter_map(|&x| x).collect();
        if valid.is_empty() {
            return None;
        }
        valid.sort_unstable();
        let mid = valid.len() / 2;
        if valid.len().is_multiple_of(2) {
            Some((valid[mid - 1] + valid[mid]) / 2)
        } else {
            Some(valid[mid])
        }
    }

    /// Calculates standard deviation jitter (in milliseconds) from successful samples.
    pub fn jitter_stddev(&self) -> f64 {
        let valid: Vec<f64> = self
            .rtt_history
            .iter()
            .filter_map(|&x| x.map(|v| v as f64))
            .collect();
        if valid.len() < 2 {
            return 0.0;
        }
        let mean = valid.iter().sum::<f64>() / valid.len() as f64;
        let variance =
            valid.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / (valid.len() - 1) as f64;
        variance.sqrt()
    }

    /// Calculates packet loss rate (0.0 = 0%, 1.0 = 100%).
    pub fn packet_loss_rate(&self) -> f64 {
        if self.rtt_history.is_empty() {
            return 0.0;
        }
        let lost = self.rtt_history.iter().filter(|x| x.is_none()).count();
        lost as f64 / self.rtt_history.len() as f64
    }

    /// Computes overall node quality score (lower is better; penalty for loss).
    pub fn score(&self, weights: &ScoringWeights) -> f64 {
        let rtt = self.median_rtt().unwrap_or(3000) as f64;
        let jitter = self.jitter_stddev();
        let loss = self.packet_loss_rate();

        // Base score with loss heavily penalizing unreachable/unstable nodes
        let base = (rtt * weights.latency_weight) + (jitter * weights.jitter_weight);
        let loss_penalty = (loss * 10_000.0) * weights.loss_weight;
        base + loss_penalty
    }
}

/// Parses "host:port", "[v6]:port", or defaults to port 443.
pub fn parse_target_addr(server: &str, default_port: u16) -> (String, u16) {
    let s = server.trim();
    if let Some((h, p)) = s.rsplit_once(':') {
        let host = h.trim_matches(|c| c == '[' || c == ']');
        let port = p
            .split('/')
            .next()
            .and_then(|x| x.parse::<u16>().ok())
            .unwrap_or(default_port);
        (host.to_string(), port)
    } else {
        (
            s.trim_matches(|c| c == '[' || c == ']').to_string(),
            default_port,
        )
    }
}

/// Measures TCP handshake latency to the server endpoint with a timeout.
pub async fn probe_tcp_connect(server: &str, default_port: u16, timeout: Duration) -> Option<u32> {
    let (host, port) = parse_target_addr(server, default_port);
    let target = format!("{host}:{port}");

    let Ok(addrs) = tokio::net::lookup_host(&target).await else {
        return None;
    };

    for addr in addrs {
        let start = Instant::now();
        if let Ok(Ok(_)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            let elapsed = start.elapsed().as_millis() as u32;
            return Some(elapsed.max(1));
        }
    }
    None
}

/// Probes real delay through the local proxy bridge (127.0.0.1:1080) or directly through a tunnel.
pub async fn probe_real_delay(
    proxy_addr: Option<&str>,
    target_url: &str,
    timeout: Duration,
) -> Option<u32> {
    let mut cmd = std::process::Command::new("curl");
    cmd.args([
        "-fsSL",
        "-o",
        "/dev/null",
        "-w",
        "%{time_total}",
        "--max-time",
        &timeout.as_secs().max(2).to_string(),
    ]);
    if let Some(proxy) = proxy_addr {
        cmd.args(["-x", proxy]);
    }
    cmd.arg(target_url);

    let output = tokio::task::spawn_blocking(move || cmd.output())
        .await
        .ok()?
        .ok()?;
    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout);
        let secs: f64 = s.trim().parse().ok()?;
        Some((secs * 1000.0).max(1.0) as u32)
    } else {
        None
    }
}

/// Measures TLS handshake latency using openssl s_client with timeout.
pub async fn probe_tls_handshake(
    server: &str,
    default_port: u16,
    sni: Option<&str>,
    timeout: Duration,
) -> Option<u32> {
    let (host, port) = parse_target_addr(server, default_port);
    let servername = sni.unwrap_or(&host).to_string();
    let target = format!("{host}:{port}");
    let timeout_secs = timeout.as_secs().max(2).to_string();

    let output = tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let status = std::process::Command::new("timeout")
            .args([
                &timeout_secs,
                "openssl",
                "s_client",
                "-connect",
                &target,
                "-servername",
                &servername,
                "-brief",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .or_else(|_| {
                // Fallback if timeout utility not present
                std::process::Command::new("openssl")
                    .args([
                        "s_client",
                        "-connect",
                        &target,
                        "-servername",
                        &servername,
                        "-brief",
                    ])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
            });
        match status {
            Ok(s) if s.success() => Some(start.elapsed().as_millis() as u32),
            _ => None,
        }
    })
    .await
    .ok()??;

    Some(output.max(1))
}

pub struct MultiLayerProber {
    semaphore: Arc<Semaphore>,
    timeout: Duration,
    proxy_addr: Option<String>,
}

impl MultiLayerProber {
    pub fn new(concurrency: usize, timeout: Duration, proxy_addr: Option<String>) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(concurrency)),
            timeout,
            proxy_addr,
        }
    }

    pub async fn probe_profile(&self, p: &Profile) -> (Option<u32>, Option<u32>, Option<u32>) {
        let _permit = self.semaphore.acquire().await.ok();
        let default_port = match p.kind {
            Kind::Wg | Kind::Awg => 51820,
            Kind::Ovpn => 1194,
            _ => 443,
        };

        // 1. TCP connect probe
        let tcp_ms = probe_tcp_connect(&p.server, default_port, self.timeout).await;

        // 2. TLS handshake probe (for TLS protocols or port 443)
        let is_tls = default_port == 443 || p.kind.is_singbox();
        let tls_ms = if is_tls && tcp_ms.is_some() {
            probe_tls_handshake(&p.server, default_port, None, self.timeout).await
        } else {
            None
        };

        // 3. Real Delay probe (if proxy bridge active or through isolated Xray instance)
        let real_delay_ms = if let Some(ref proxy) = self.proxy_addr {
            probe_real_delay(Some(proxy), DEFAULT_PROBE_URL, self.timeout).await
        } else if p.kind.is_xray_capable() && crate::xray::resolve_xray_binary().is_ok() {
            let p_clone = p.clone();
            let to = self.timeout;
            tokio::task::spawn_blocking(move || {
                crate::xray::XrayBackend::new()
                    .probe_real_delay(&p_clone, to)
                    .ok()
            })
            .await
            .ok()
            .flatten()
        } else {
            None
        };

        (tcp_ms, tls_ms, real_delay_ms)
    }
}

/// Chooses the optimal node from a candidate list according to selection mode.
pub fn select_best_node<'a>(
    profiles: &'a [Profile],
    metrics_map: &std::collections::HashMap<String, NodeMetrics>,
    mode: SelectionMode,
    weights: &ScoringWeights,
) -> Option<&'a Profile> {
    if profiles.is_empty() {
        return None;
    }

    match mode {
        SelectionMode::Manual => profiles.first(),
        SelectionMode::FallbackGroup => {
            // Pick first node with median RTT and loss < 50%
            profiles
                .iter()
                .find(|p| {
                    if let Some(m) = metrics_map.get(&p.id) {
                        m.packet_loss_rate() < 0.50 && m.median_rtt().is_some()
                    } else {
                        true
                    }
                })
                .or_else(|| profiles.first())
        }
        SelectionMode::AutoBest | SelectionMode::LoadBalanceGroup => {
            // Sort by score ascending (lowest penalty score is best)
            let mut scored: Vec<(&Profile, f64)> = profiles
                .iter()
                .map(|p| {
                    let sc = metrics_map
                        .get(&p.id)
                        .map(|m| m.score(weights))
                        .unwrap_or(999.0);
                    (p, sc)
                })
                .collect();
            scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            scored.first().map(|(p, _)| *p)
        }
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Computes backoff duration with exponential factor and jitter.
pub fn exponential_backoff_with_jitter(attempt: u32, base_ms: u64, max_ms: u64) -> Duration {
    let factor = 2u64.saturating_pow(attempt.min(6));
    let raw = (base_ms * factor).min(max_ms);
    let jitter = now_secs() % 250;
    Duration::from_millis(raw + jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_metrics_median_and_jitter() {
        let mut m = NodeMetrics::new();
        m.record_sample(Some(50));
        m.record_sample(Some(60));
        m.record_sample(Some(40));
        m.record_sample(Some(50));
        m.record_sample(Some(55));

        assert_eq!(m.median_rtt(), Some(50));
        assert!(m.jitter_stddev() > 0.0);
        assert_eq!(m.packet_loss_rate(), 0.0);

        m.record_sample(None);
        assert!(m.packet_loss_rate() > 0.0);
    }

    #[test]
    fn test_scoring_prefers_lower_latency_and_loss() {
        let weights = ScoringWeights::default();

        let mut m_good = NodeMetrics::new();
        m_good.record_sample(Some(30));
        m_good.record_sample(Some(35));
        m_good.record_sample(Some(32));

        let mut m_lossy = NodeMetrics::new();
        m_lossy.record_sample(Some(30));
        m_lossy.record_sample(None);
        m_lossy.record_sample(None);

        let score_good = m_good.score(&weights);
        let score_lossy = m_lossy.score(&weights);

        assert!(
            score_good < score_lossy,
            "Healthy node must score better than lossy node"
        );
    }

    #[test]
    fn test_select_best_node_auto_best() {
        let p1 = Profile::new("n1", "Node 1", Kind::Vless, "1.1.1.1:443", "");
        let p2 = Profile::new("n2", "Node 2", Kind::Vless, "2.2.2.2:443", "");
        let profiles = vec![p1.clone(), p2.clone()];

        let mut map = std::collections::HashMap::new();
        let mut m1 = NodeMetrics::new();
        m1.record_sample(Some(120));
        map.insert("n1".into(), m1);

        let mut m2 = NodeMetrics::new();
        m2.record_sample(Some(45));
        map.insert("n2".into(), m2);

        let best = select_best_node(
            &profiles,
            &map,
            SelectionMode::AutoBest,
            &ScoringWeights::default(),
        );
        assert_eq!(best.unwrap().id, "n2");
    }

    #[test]
    fn test_exponential_backoff() {
        let d0 = exponential_backoff_with_jitter(0, 1000, 10000);
        let d3 = exponential_backoff_with_jitter(3, 1000, 10000);
        assert!(d3 > d0);
    }
}
