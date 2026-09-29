use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SpeedResult {
    pub bytes: u64,
    pub duration_secs: f64,
    pub mbps: f64,
    pub mbs: f64,
}

pub const DEFAULT_TEST_DURATION_SECS: u64 = 6;

pub fn run_speed_test(timeout_secs: u64) -> Result<SpeedResult> {
    let endpoints = [
        "https://speed.cloudflare.com/__down?bytes=25000000",
        "https://cachefly.cachefly.net/10mb.test",
        "https://speed.hetzner.de/100MB.bin",
    ];

    let t_str = timeout_secs.max(2).to_string();

    for url in endpoints {
        let out = Command::new("curl")
            .args([
                "-fsSL",
                "--max-time",
                &t_str,
                "-w",
                "%{time_total}:%{size_download}:%{speed_download}",
                "-o",
                "/dev/null",
                url,
            ])
            .output();

        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 3 {
                let duration: f64 = parts[0].parse().unwrap_or(0.0);
                let bytes: u64 = parts[1].parse::<f64>().map(|b| b as u64).unwrap_or(0);
                let speed_bytes: f64 = parts[2].parse().unwrap_or(0.0);

                if bytes > 1024 && duration > 0.0 {
                    let mbps = (speed_bytes * 8.0) / 1_000_000.0;
                    let mbs = speed_bytes / 1_048_576.0;
                    return Ok(SpeedResult {
                        bytes,
                        duration_secs: duration,
                        mbps,
                        mbs,
                    });
                }
            }
        }
    }

    bail!("all speed test endpoints timed out or failed to transfer data")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speed_result_calc() {
        let res = SpeedResult {
            bytes: 10_000_000,
            duration_secs: 2.0,
            mbps: 40.0,
            mbs: 5.0,
        };
        assert_eq!(res.bytes, 10_000_000);
        assert!((res.mbps - 40.0).abs() < f64::EPSILON);
    }
}
