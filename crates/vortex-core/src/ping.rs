//! Latency measurement for profiles (server reachability) and for the live tunnel.
//!
//! * TCP-based protocols (VLESS / VMess / Trojan / SS / TCP OpenVPN): time of a TCP handshake.
//! * UDP-based protocols (Hysteria2 / TUIC / WireGuard / AmneziaWG / UDP OpenVPN): ICMP echo,
//!   falling back to a TCP handshake when ICMP is filtered.

use crate::store::{Kind, Profile};
use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ping {
    Ms(u32),
    Timeout,
}

fn parse_port(s: &str) -> Option<u16> {
    let d: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    d.parse().ok()
}

/// "host:port", "[v6]:port", "host:20000-30000" (port hopping), bare "host".
pub fn split_host_port(server: &str, default: u16) -> Option<(String, u16)> {
    let s = server.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(parse_port)
            .unwrap_or(default);
        return Some((h.to_string(), port));
    }
    if s.matches(':').count() == 1 {
        let (h, p) = s.split_once(':')?;
        return Some((h.to_string(), parse_port(p).unwrap_or(default)));
    }
    Some((s.to_string(), default))
}

fn default_port(k: Kind) -> u16 {
    match k {
        Kind::Wg | Kind::Awg => 51820,
        Kind::Ovpn => 1194,
        _ => 443,
    }
}

/// Does this profile talk UDP (so a TCP handshake to its port is meaningless)?
pub fn uses_icmp(p: &Profile) -> bool {
    match p.kind {
        Kind::Hy2 | Kind::Tuic | Kind::Wg | Kind::Awg => true,
        Kind::Ovpn => p.data.lines().any(|l| {
            let mut it = l.split_whitespace();
            match it.next() {
                Some("proto") => it.next().map(|v| v.starts_with("udp")).unwrap_or(false),
                Some("remote") => it.nth(2).map(|v| v.starts_with("udp")).unwrap_or(false),
                _ => false,
            }
        }),
        _ => false,
    }
}

fn tcp_ms(host: &str, port: u16, timeout: Duration) -> Option<u32> {
    let addrs = (host, port).to_socket_addrs().ok()?;
    for a in addrs.take(2) {
        let t = Instant::now();
        if TcpStream::connect_timeout(&a, timeout).is_ok() {
            let elapsed = t.elapsed().as_micros();
            return Some(((elapsed + 500) / 1000).max(1) as u32);
        }
    }
    None
}

fn icmp_ms(host: &str) -> Option<u32> {
    if host.starts_with('-') {
        return None;
    }
    let out = Command::new("ping")
        .args(["-n", "-q", "-c", "1", "-W", "1", host])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().find(|l| l.contains("min/avg/max"))?;
    let avg: f64 = line
        .split('=')
        .nth(1)?
        .trim()
        .split('/')
        .nth(1)?
        .trim()
        .parse()
        .ok()?;
    Some(avg.round().max(1.0) as u32)
}

/// Latency to a profile's server.
pub fn measure(p: &Profile) -> Ping {
    let Some((host, port)) = split_host_port(&p.server, default_port(p.kind)) else {
        return Ping::Timeout;
    };
    let t = Duration::from_millis(1500);
    let ms = if uses_icmp(p) {
        icmp_ms(&host).or_else(|| tcp_ms(&host, port, t))
    } else {
        tcp_ms(&host, port, t)
    };
    ms.map(Ping::Ms).unwrap_or(Ping::Timeout)
}

/// One RTT sample through whatever the default route is (i.e. the tunnel when connected).
pub fn probe() -> Option<u32> {
    let a: SocketAddr = "1.1.1.1:443".parse().ok()?;
    let t = Instant::now();
    TcpStream::connect_timeout(&a, Duration::from_millis(2000)).ok()?;
    Some((t.elapsed().as_micros() as u32 / 1000).max(1))
}

/// Measure many profiles in parallel; `done` is called from worker threads as results arrive.
/// Returns immediately.
pub fn run_pool<F>(mut jobs: Vec<Profile>, workers: usize, done: F)
where
    F: Fn(String, Ping) + Send + Sync + 'static,
{
    jobs.reverse(); // workers pop from the back → original order
    let n = workers.min(jobs.len());
    let q = Arc::new(Mutex::new(jobs));
    let done = Arc::new(done);
    for _ in 0..n {
        let q = q.clone();
        let done = done.clone();
        thread::spawn(move || loop {
            let job = q.lock().ok().and_then(|mut v| v.pop());
            let Some(p) = job else { break };
            let r = measure(&p);
            done(p.id.clone(), r);
        });
    }
}

/// Blocking helper for the CLI: measure everything, return sorted (fastest first, timeouts last).
pub fn measure_all(profiles: Vec<Profile>) -> Vec<(Profile, Ping)> {
    let (tx, rx) = std::sync::mpsc::channel();
    let n = profiles.len();
    let tx = Mutex::new(tx);
    run_pool(profiles.clone(), 16, move |id, r| {
        if let Ok(tx) = tx.lock() {
            let _ = tx.send((id, r));
        }
    });
    let mut got = std::collections::HashMap::new();
    for _ in 0..n {
        match rx.recv() {
            Ok((id, r)) => {
                got.insert(id, r);
            }
            Err(_) => break,
        }
    }
    let mut v: Vec<(Profile, Ping)> = profiles
        .into_iter()
        .map(|p| {
            let r = got.get(&p.id).copied().unwrap_or(Ping::Timeout);
            (p, r)
        })
        .collect();
    v.sort_by_key(|(_, r)| match r {
        Ping::Ms(m) => (0, *m),
        Ping::Timeout => (1, 0),
    });
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port() {
        assert_eq!(
            split_host_port("1.2.3.4:5555", 443),
            Some(("1.2.3.4".into(), 5555))
        );
        assert_eq!(
            split_host_port("[::1]:8443", 443),
            Some(("::1".into(), 8443))
        );
        assert_eq!(
            split_host_port("a.b:20000-30000", 443),
            Some(("a.b".into(), 20000))
        );
        assert_eq!(
            split_host_port("example.com", 51820),
            Some(("example.com".into(), 51820))
        );
        assert_eq!(split_host_port("", 443), None);
    }
}
