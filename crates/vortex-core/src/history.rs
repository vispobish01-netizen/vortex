use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn default_history_path() -> PathBuf {
    if let Ok(dir) = std::env::var("VORTEX_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("history.json");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local/share/vortex/history.json")
    } else {
        PathBuf::from("/tmp/vortex-history.json")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TrafficRecord {
    pub timestamp: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct TrafficHistory {
    pub hourly: Vec<TrafficRecord>,
    pub daily: Vec<TrafficRecord>,
    pub total_rx: u64,
    pub total_tx: u64,
}

impl TrafficHistory {
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(path)
            .with_context(|| format!("Failed to read history from {path:?}"))?;
        let history: Self = serde_json::from_str(&data)
            .with_context(|| format!("Failed to deserialize traffic history from {path:?}"))?;
        Ok(history)
    }

    pub fn load() -> Self {
        let p = default_history_path();
        Self::load_from(&p).unwrap_or_default()
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json =
            serde_json::to_string_pretty(self).context("Failed to serialize traffic history")?;

        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        fs::write(&tmp, json)
            .with_context(|| format!("Failed to write temporary history file at {tmp:?}"))?;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));

        fs::rename(&tmp, path)
            .with_context(|| format!("Failed to atomically rename {tmp:?} to {path:?}"))?;
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        let p = default_history_path();
        self.save_to(&p)
    }

    pub fn record_sample(
        &mut self,
        rx: u64,
        tx: u64,
        node_id: Option<&str>,
        node_name: Option<&str>,
        protocol: Option<&str>,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.total_rx = self.total_rx.saturating_add(rx);
        self.total_tx = self.total_tx.saturating_add(tx);

        let hour_ts = (now / 3600) * 3600;
        let day_ts = (now / 86400) * 86400;

        // Aggregate hourly
        if let Some(last) = self.hourly.last_mut().filter(|h| h.timestamp == hour_ts) {
            last.rx_bytes = last.rx_bytes.saturating_add(rx);
            last.tx_bytes = last.tx_bytes.saturating_add(tx);
        } else {
            self.hourly.push(TrafficRecord {
                timestamp: hour_ts,
                rx_bytes: rx,
                tx_bytes: tx,
                node_id: node_id.map(String::from),
                node_name: node_name.map(String::from),
                protocol: protocol.map(String::from),
            });
            if self.hourly.len() > 720 {
                self.hourly.remove(0);
            }
        }

        // Aggregate daily
        if let Some(last) = self.daily.last_mut().filter(|d| d.timestamp == day_ts) {
            last.rx_bytes = last.rx_bytes.saturating_add(rx);
            last.tx_bytes = last.tx_bytes.saturating_add(tx);
        } else {
            self.daily.push(TrafficRecord {
                timestamp: day_ts,
                rx_bytes: rx,
                tx_bytes: tx,
                node_id: node_id.map(String::from),
                node_name: node_name.map(String::from),
                protocol: protocol.map(String::from),
            });
            if self.daily.len() > 365 {
                self.daily.remove(0);
            }
        }
    }

    pub fn export_json(&self, since_secs: Option<u64>) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = since_secs.map(|s| now.saturating_sub(s)).unwrap_or(0);

        let filtered_hourly: Vec<&TrafficRecord> = self
            .hourly
            .iter()
            .filter(|r| r.timestamp >= cutoff)
            .collect();
        let filtered_daily: Vec<&TrafficRecord> = self
            .daily
            .iter()
            .filter(|r| r.timestamp >= cutoff)
            .collect();

        serde_json::to_string_pretty(&serde_json::json!({
            "total_rx": self.total_rx,
            "total_tx": self.total_tx,
            "hourly": filtered_hourly,
            "daily": filtered_daily,
        }))
        .unwrap_or_default()
    }

    pub fn export_csv(&self, since_secs: Option<u64>) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = since_secs.map(|s| now.saturating_sub(s)).unwrap_or(0);

        let mut out = String::from("type,timestamp,rx_bytes,tx_bytes,node_id,node_name,protocol\n");
        for r in self.daily.iter().filter(|r| r.timestamp >= cutoff) {
            out.push_str(&format!(
                "daily,{},{},{},{},{},{}\n",
                r.timestamp,
                r.rx_bytes,
                r.tx_bytes,
                r.node_id.as_deref().unwrap_or(""),
                r.node_name.as_deref().unwrap_or(""),
                r.protocol.as_deref().unwrap_or(""),
            ));
        }
        for r in self.hourly.iter().filter(|r| r.timestamp >= cutoff) {
            out.push_str(&format!(
                "hourly,{},{},{},{},{},{}\n",
                r.timestamp,
                r.rx_bytes,
                r.tx_bytes,
                r.node_id.as_deref().unwrap_or(""),
                r.node_name.as_deref().unwrap_or(""),
                r.protocol.as_deref().unwrap_or(""),
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_history_record_and_aggregate() {
        let mut hist = TrafficHistory::default();
        hist.record_sample(1000, 500, Some("n1"), Some("Node 1"), Some("vless"));
        hist.record_sample(2000, 1500, Some("n1"), Some("Node 1"), Some("vless"));

        assert_eq!(hist.total_rx, 3000);
        assert_eq!(hist.total_tx, 2000);
        assert_eq!(hist.hourly.len(), 1);
        assert_eq!(hist.hourly[0].rx_bytes, 3000);
        assert_eq!(hist.hourly[0].tx_bytes, 2000);

        let json = hist.export_json(None);
        assert!(json.contains("3000"));

        let csv = hist.export_csv(None);
        assert!(csv.contains("hourly"));
        assert!(csv.contains("3000"));
    }
}
