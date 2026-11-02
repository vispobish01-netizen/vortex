use super::*;
use crate::keymap::{self, Action, ConfirmKind, Mode};
use anyhow::Result;
use crossterm::{
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
        Event, KeyEvent, MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{prelude::*, widgets::*};
use std::{
    collections::{HashMap, HashSet},
    io::stdout,
    process::Command,
    sync::{
        mpsc::{self, Receiver, Sender},
        Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use vortex_core::benchmark::{self, SpeedResult};
use vortex_core::model::OperationalMode;
use vortex_core::ping::{self, Ping};
use vortex_core::recon::{self, ReconReport};
use vortex_core::shield;
use vortex_core::store::{self, Kind, Profile, Security, Transport};
use vortex_core::tunnel::{self, ActiveFlow, Session};

#[allow(clippy::large_enum_variant)]
pub(crate) enum Msg {
    Connected(Result<Session, String>),
    Disconnected(Result<(), String>),
    Imported(Result<usize, String>),
    SubsUpdated(Result<usize, String>),
    Ip(String),
    Ping(String, Ping),
    Rtt(Option<u32>),
    ReconDone(Result<ReconReport, String>),
    SpeedDone(Result<SpeedResult, String>),
    Flows(Vec<ActiveFlow>),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortMode {
    #[default]
    Name,
    Latency,
    Transport,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportFilter {
    #[default]
    All,
    Tcp,
    Udp,
}

impl TransportFilter {
    pub fn cycle(&self) -> Self {
        match self {
            TransportFilter::All => TransportFilter::Tcp,
            TransportFilter::Tcp => TransportFilter::Udp,
            TransportFilter::Udp => TransportFilter::All,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            TransportFilter::All => "ALL",
            TransportFilter::Tcp => "TCP",
            TransportFilter::Udp => "UDP",
        }
    }

    pub fn matches_profile(&self, p: &Profile) -> bool {
        match self {
            TransportFilter::All => true,
            TransportFilter::Tcp => p.transport.is_tcp(),
            TransportFilter::Udp => p.transport.is_udp(),
        }
    }

    pub fn matches_flow(&self, f: &ActiveFlow) -> bool {
        match self {
            TransportFilter::All => true,
            TransportFilter::Tcp => f.network.eq_ignore_ascii_case("tcp"),
            TransportFilter::Udp => f.network.eq_ignore_ascii_case("udp"),
        }
    }
}


pub struct App {
    pub(crate) profiles: Vec<Profile>,
    /// indices into `profiles` after filter + sort
    pub(crate) view: Vec<usize>,
    pub(crate) list: ListState,
    pub(crate) filter: String,
    pub(crate) sort_ping: bool,
    pub(crate) sort_mode: SortMode,
    pub(crate) transport_filter: TransportFilter,
    pub(crate) flows_filter: TransportFilter,
    pub(crate) mode: Mode,
    pub(crate) focused_panel: usize,
    pub(crate) session: Option<Session>,
    pub(crate) busy: Option<&'static str>,
    pub(crate) busy_since: Instant,
    pub(crate) toast: Option<(String, bool, Instant)>,
    pub(crate) show_log: bool,
    pub(crate) show_flows: bool,
    pub(crate) flows: Vec<ActiveFlow>,
    pub(crate) last_flows_tick: Instant,
    pub(crate) shield_armed: bool,
    pub(crate) down: Vec<u64>,
    pub(crate) up: Vec<u64>,
    pub(crate) down_peak: u64,
    pub(crate) up_peak: u64,
    pub(crate) rtt_hist: Vec<u64>,
    pub(crate) rtt: Option<u32>,
    pub(crate) rtt_busy: bool,
    pub(crate) last_rtt: Instant,
    pub(crate) last: Option<(u64, u64)>,
    pub(crate) base: (u64, u64),
    pub(crate) last_tick: Instant,
    pub(crate) ip: String,
    pub(crate) pings: HashMap<String, Ping>,
    pub(crate) pending: HashSet<String>,
    pub(crate) qr_profile: Option<Profile>,
    pub(crate) qr_code: Option<Result<String, String>>,
    pub(crate) qr_exported: Option<String>,
    pub(crate) subs: Vec<store::Subscription>,
    pub(crate) subs_list: ListState,
    pub(crate) rules_cfg: vortex_core::routing::RulesConfig,
    pub(crate) rules_list: ListState,
    pub(crate) recon_report: Option<Result<ReconReport, String>>,
    pub(crate) speed_result: Option<SpeedResult>,
    pub(crate) speed_running: bool,
    pub(crate) tx: Sender<Msg>,
    pub(crate) rx: Receiver<Msg>,
}


pub(crate) fn push(v: &mut Vec<u64>, x: u64) {
    v.push(x);
    if v.len() > HIST {
        v.remove(0);
    }
}


impl App {
    pub(crate) fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let mut a = App {
            profiles: store::load_all(),
            view: vec![],
            list: ListState::default(),
            filter: String::new(),
            sort_ping: false,
            sort_mode: SortMode::Name,
            transport_filter: TransportFilter::All,
            flows_filter: TransportFilter::All,
            mode: Mode::Normal,
            focused_panel: 1,
            session: tunnel::load_session(),
            busy: None,
            busy_since: Instant::now(),
            toast: None,
            show_log: false,
            show_flows: false,
            flows: vec![],
            last_flows_tick: Instant::now(),
            shield_armed: shield::is_armed(),
            down: vec![],
            up: vec![],
            down_peak: 0,
            up_peak: 0,
            rtt_hist: vec![],
            rtt: None,
            rtt_busy: false,
            last_rtt: Instant::now(),
            last: None,
            base: (0, 0),
            last_tick: Instant::now(),
            ip: String::new(),
            pings: HashMap::new(),
            pending: HashSet::new(),
            qr_profile: None,
            qr_code: None,
            qr_exported: None,
            subs: vec![],
            subs_list: ListState::default(),
            rules_cfg: vortex_core::routing::RulesConfig::default(),
            rules_list: ListState::default(),
            recon_report: None,
            speed_result: None,
            speed_running: false,
            tx,
            rx,
        };
        a.rebuild();
        // start on the active profile, else the one used last time
        let want = a
            .session
            .as_ref()
            .map(|s| s.id.clone())
            .or_else(store::last);
        if let Some(id) = want {
            if let Some(i) = a.view.iter().position(|&i| a.profiles[i].id == id) {
                a.list.select(Some(i));
            }
        }
        if let Some(s) = &a.session {
            a.base = tunnel::bytes(&s.iface).unwrap_or((0, 0));
            a.spawn_ip();
        } else {
            a.test(false); // fresh latency numbers on launch
            let preflight = vortex_core::privilege::run_preflight_check();
            if !preflight.is_root && !preflight.singbox_has_caps {
                if !preflight.tun_device_exists {
                    a.toast = Some((
                        "PREFLIGHT: /dev/net/tun missing — run `sudo modprobe tun`".into(),
                        false,
                        Instant::now(),
                    ));
                } else if !preflight.can_sudo_passwordless {
                    a.toast = Some((
                        "PREFLIGHT: sing-box lacks CAP_NET_ADMIN — run `vortex setup` for passwordless TUN".into(),
                        false,
                        Instant::now(),
                    ));
                }
            }
        }
        a
    }

    pub(crate) fn cur(&self) -> Option<&Profile> {
        let idx = *self.view.get(self.list.selected()?)?;
        self.profiles.get(idx)
    }

    pub(crate) fn toast(&mut self, m: impl Into<String>, ok: bool) {
        self.toast = Some((m.into(), ok, Instant::now()));
    }

    pub(crate) fn rebuild(&mut self) {
        let keep = self.cur().map(|p| p.id.clone());
        let f = self.filter.to_lowercase();
        let clean_f = f.trim_start_matches('/');
        let mut v: Vec<usize> = (0..self.profiles.len())
            .filter(|&i| {
                let p = &self.profiles[i];
                if !self.transport_filter.matches_profile(p) {
                    return false;
                }
                if f.is_empty() {
                    return true;
                }
                let t_disp = p.display_transport().to_lowercase();
                let matches_target = |s: &str| {
                    let sl = s.to_lowercase();
                    sl.contains(&f) || (!clean_f.is_empty() && sl.contains(clean_f))
                };
                matches_target(&p.name)
                    || matches_target(p.kind.tag())
                    || matches_target(&p.server)
                    || matches_target(&t_disp)
                    || (clean_f == "udp" && p.transport.is_udp())
                    || (clean_f == "tcp" && p.transport.is_tcp())
                    || (clean_f == "ws" && p.transport == Transport::Ws)
                    || (clean_f == "grpc" && p.transport == Transport::Grpc)
                    || (clean_f == "quic" && p.transport == Transport::Quic)
                    || (clean_f == "reality" && p.security == Security::Reality)
            })
            .collect();
        match self.sort_mode {
            SortMode::Latency => {
                v.sort_by_key(|&i| match self.pings.get(&self.profiles[i].id) {
                    Some(Ping::Ms(m)) => (0, *m),
                    None => (1, 0),
                    Some(Ping::Timeout) => (2, 0),
                });
            }
            SortMode::Transport => {
                v.sort_by(|&a, &b| {
                    let pa = &self.profiles[a];
                    let pb = &self.profiles[b];
                    pa.display_transport()
                        .cmp(&pb.display_transport())
                        .then_with(|| pa.name.to_lowercase().cmp(&pb.name.to_lowercase()))
                });
            }
            SortMode::Name => {
                if self.sort_ping {
                    v.sort_by_key(|&i| match self.pings.get(&self.profiles[i].id) {
                        Some(Ping::Ms(m)) => (0, *m),
                        None => (1, 0),
                        Some(Ping::Timeout) => (2, 0),
                    });
                }
            }
        }
        self.view = v;
        let idx = if self.sort_ping {
            0
        } else {
            keep.and_then(|id| {
                self.view
                    .iter()
                    .position(|&i| self.profiles.get(i).map(|p| &p.id) == Some(&id))
            })
            .unwrap_or(0)
        };
        self.list.select(if self.view.is_empty() {
            None
        } else {
            Some(idx.min(self.view.len() - 1))
        });
    }

    pub(crate) fn reload(&mut self) {
        self.profiles = store::load_all();
        self.pings
            .retain(|id, _| self.profiles.iter().any(|p| &p.id == id));
        self.rebuild();
    }

    pub(crate) fn start(&mut self, what: &'static str) {
        self.busy = Some(what);
        self.busy_since = Instant::now();
    }

    pub(crate) fn spawn_ip(&self) {
        let tx = self.tx.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(1200));
            let _ = tx.send(Msg::Ip(tunnel::public_ip()));
        });
    }

    /// latency-test the visible profiles (or just the selected one)
    pub(crate) fn test(&mut self, only_selected: bool) {
        if self.session.is_some() {
            return self.toast(
                "disconnect first — server latency can't be measured through the tunnel",
                false,
            );
        }
        let jobs: Vec<Profile> = if only_selected {
            self.cur().cloned().into_iter().collect()
        } else {
            self.view
                .iter()
                .map(|&i| self.profiles[i].clone())
                .collect()
        };
        if jobs.is_empty() {
            return;
        }
        for p in &jobs {
            self.pending.insert(p.id.clone());
        }
        let tx = Mutex::new(self.tx.clone());
        ping::run_pool(jobs, 12, move |id, r| {
            if let Ok(t) = tx.lock() {
                let _ = t.send(Msg::Ping(id, r));
            }
        });
    }

    pub(crate) fn connect(&mut self) {
        if self.busy.is_some() {
            return;
        }
        let Some(mut p) = self.cur().cloned() else {
            return;
        };
        let creds = if tunnel::ovpn_needs_auth(&p) {
            if let Some(ref a) = p.auth {
                Some((a.username.clone(), a.password.clone()))
            } else {
                let _ = restore();
                let result = tunnel::prompt_ovpn_credentials(None);
                let _ = enable_raw_mode();
                let _ = execute!(stdout(), EnterAlternateScreen, EnableBracketedPaste);
                match result {
                    Ok(c) => {
                        if c.save {
                            p.auth = Some(store::Auth {
                                username: c.username.clone(),
                                password: c.password.clone(),
                                save: true,
                            });
                            let _ = store::save(&p);
                            self.reload();
                        }
                        Some((c.username, c.password))
                    }
                    Err(e) => {
                        self.toast(format!("{e:#}"), false);
                        return;
                    }
                }
            }
        } else {
            None
        };

        let is_proxy_only = vortex_core::storage::get_mode_preference().is_proxy()
            || p.backend_type.as_deref() == Some("proxy")
            || std::env::var("VORTEX_MODE")
                .map(|m| m.eq_ignore_ascii_case("proxy"))
                .unwrap_or(false);

        if !is_proxy_only && p.kind != Kind::Ovpn {
            let preflight = vortex_core::privilege::run_preflight_check();
            if !preflight.is_root && !preflight.singbox_has_caps && !preflight.can_sudo_passwordless
            {
                let _ = restore();
                println!(
                    "\r\n\x1b[1;36m◈ VORTEX // ELEVATION REQUIRED FOR SYSTEM TUN TUNNEL\x1b[0m"
                );
                println!("  sing-box requires root privileges (or CAP_NET_ADMIN) to configure network interfaces.");
                println!("  (Tip: Run `vortex setup` to grant passwordless capabilities so you won't be prompted.)\r\n");
                let status = std::process::Command::new("sudo").arg("-v").status();
                let _ = enable_raw_mode();
                let _ = execute!(stdout(), EnterAlternateScreen, EnableBracketedPaste);
                match status {
                    Ok(s) if s.success() => {}
                    _ => {
                        self.toast(
                            "ELEVATION CANCELLED // ROOT PRIVILEGES REQUIRED FOR TUN",
                            false,
                        );
                        return;
                    }
                }
            }
        }

        self.start("connecting");
        self.ip.clear();
        let tx = self.tx.clone();
        thread::spawn(move || {
            let r = tunnel::connect_with_credentials(
                &p,
                creds.as_ref().map(|(u, pw)| (u.as_str(), pw.as_str())),
            )
            .map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::Connected(r));
        });
    }

    pub(crate) fn manage_auth(&mut self) {
        let Some(mut p) = self.cur().cloned() else {
            return;
        };
        if p.kind != Kind::Ovpn {
            self.toast("credentials only apply to OpenVPN profiles", false);
            return;
        }
        let _ = restore();
        let default_user = p.auth.as_ref().map(|a| a.username.as_str());
        let result = tunnel::prompt_ovpn_credentials(default_user);
        let _ = enable_raw_mode();
        let _ = execute!(stdout(), EnterAlternateScreen, EnableBracketedPaste);
        match result {
            Ok(c) => {
                if c.save {
                    p.auth = Some(store::Auth {
                        username: c.username,
                        password: c.password,
                        save: true,
                    });
                    if let Err(e) = store::save(&p) {
                        self.toast(format!("could not save: {e}"), false);
                        return;
                    }
                    self.reload();
                    self.toast("credentials saved", true);
                } else {
                    let _ = store::clear_auth(&p.id);
                    self.reload();
                    self.toast("credentials cleared", false);
                }
            }
            Err(e) => self.toast(format!("{e:#}"), false),
        }
    }

    pub(crate) fn disconnect(&mut self) {
        if self.busy.is_some() || self.session.is_none() {
            return;
        }
        self.start("disconnecting");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let r = tunnel::disconnect().map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::Disconnected(r));
        });
    }

    pub(crate) fn import(&mut self, s: String) {
        if self.busy.is_some() {
            return;
        }
        self.start("importing");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let r = store::import(&s).map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::Imported(r));
        });
    }

    pub(crate) fn delete(&mut self) {
        let Some(p) = self.cur().cloned() else { return };
        if self.session.as_ref().map(|s| s.id == p.id).unwrap_or(false) {
            return self.toast("disconnect first", false);
        }
        match store::remove(&p.id) {
            Ok(()) => {
                self.reload();
                self.toast(format!("deleted {}", p.name), true);
            }
            Err(e) => self.toast(format!("{e}"), false),
        }
    }

    pub(crate) fn rename(&mut self, name: String) {
        let Some(id) = self.cur().map(|p| p.id.clone()) else {
            return;
        };
        match store::rename(&id, &name) {
            Ok(()) => {
                if let Some(s) = self.session.as_mut().filter(|s| s.id == id) {
                    s.name = name.trim().to_string();
                }
                self.reload();
                self.toast("renamed", true);
            }
            Err(e) => self.toast(format!("{e:#}"), false),
        }
    }

    pub(crate) fn sync_subs(&mut self) {
        if self.busy.is_some() {
            return;
        }
        self.start("syncing subscriptions");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let r = store::update_all_subs()
                .map(|results| {
                    let total: usize = results.iter().filter_map(|(_, r)| r.as_ref().ok()).sum();
                    total
                })
                .map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::SubsUpdated(r));
        });
    }

    pub(crate) fn sync_single_sub(&mut self, id: String) {
        if self.busy.is_some() {
            return;
        }
        self.start("updating sub");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let r = store::update_sub(&id)
                .map(|(_, count)| count)
                .map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::SubsUpdated(r));
        });
    }

    pub(crate) fn paste_clip(&mut self) {
        let get_text = || -> Option<String> {
            if let Ok(u) = std::env::var("SUDO_USER") {
                if !u.is_empty() && u != "root" {
                    if let Ok(o) = Command::new("sudo")
                        .args(["-u", &u, "wl-paste", "-n"])
                        .output()
                    {
                        if o.status.success() {
                            let s = String::from_utf8_lossy(&o.stdout).to_string();
                            if !s.trim().is_empty() {
                                return Some(s);
                            }
                        }
                    }
                }
            }
            if let Ok(o) = Command::new("wl-paste").arg("-n").output() {
                if o.status.success() {
                    let s = String::from_utf8_lossy(&o.stdout).to_string();
                    if !s.trim().is_empty() {
                        return Some(s);
                    }
                }
            }
            None
        };

        if let Some(s) = get_text() {
            return self.import(s);
        }

        match store::scan_clipboard_qr() {
            Ok(s) => {
                self.toast("DECODED QR PAYLOAD FROM CLIPBOARD IMAGE", true);
                self.import(s);
            }
            Err(_) => self.toast("clipboard empty — or paste with ctrl+shift+v", false),
        }
    }

    /// bracketed paste from the terminal
    pub(crate) fn paste(&mut self, s: String) {
        match &mut self.mode {
            Mode::Add(i) | Mode::Edit(i) => i.push_str(s.trim()),
            Mode::Search(i) => {
                i.push_str(s.trim());
                self.filter = i.clone();
                self.rebuild();
            }
            Mode::Normal => self.import(s),
            _ => {}
        }
    }

    pub(crate) fn mv(&mut self, d: i32) {
        let n = self.view.len() as i32;
        if n > 0 {
            let cur = self.list.selected().unwrap_or(0) as i32;
            self.list.select(Some((cur + d).rem_euclid(n) as usize));
        }
    }

    pub(crate) fn drain(&mut self) -> bool {
        let mut changed = false;
        while let Ok(m) = self.rx.try_recv() {
            changed = true;
            match m {
                Msg::Connected(Ok(s)) => {
                    self.busy = None;
                    self.base = tunnel::bytes(&s.iface).unwrap_or((0, 0));
                    self.last = None;
                    self.down.clear();
                    self.up.clear();
                    self.down_peak = 0;
                    self.up_peak = 0;
                    self.rtt_hist.clear();
                    self.rtt = None;
                    self.toast(format!("TUNNEL ENGAGED // TARGET: {}", s.name), true);
                    self.session = Some(s);
                    self.spawn_ip();
                }
                Msg::Connected(Err(e)) => {
                    self.busy = None;
                    self.session = tunnel::load_session();
                    let toast_msg = if e.contains("CAP_NET_ADMIN")
                        || e.contains("TUNSETIFF")
                        || e.contains("PRIVILEGE ERROR")
                    {
                        "PRIVILEGE ERROR: sing-box needs CAP_NET_ADMIN for TUN. Run `vortex setup` or press 'l' for log".to_string()
                    } else {
                        format!("CONNECT ERROR: {e} [press 'l' for log]")
                    };
                    self.toast(toast_msg, false);
                }
                Msg::Disconnected(r) => {
                    self.busy = None;
                    self.session = None;
                    self.ip.clear();
                    self.rtt = None;
                    self.down_peak = 0;
                    self.up_peak = 0;
                    match r {
                        Ok(()) => self.toast("TUNNEL SEVERED // ROUTE DISENGAGED", true),
                        Err(e) => self.toast(format!("TERMINATION ERR: {e}"), false),
                    }
                }
                Msg::Imported(Ok(n)) => {
                    self.busy = None;
                    self.reload();
                    if n == 0 {
                        self.toast("PAYLOAD DUPLICATE // ZERO PROFILES INJECTED", false);
                    } else {
                        self.toast(format!("INJECTION SUCCESSFUL // {n} NODE(S) ARMED"), true);
                        self.test(false);
                    }
                }
                Msg::Imported(Err(e)) => {
                    self.busy = None;
                    self.toast(format!("PAYLOAD REJECTED: {e}"), false);
                }
                Msg::SubsUpdated(Ok(n)) => {
                    self.busy = None;
                    self.reload();
                    self.toast(format!("SUBSCRIPTIONS SYNCED // {n} NODE(S) UPDATED"), true);
                    self.test(false);
                }
                Msg::SubsUpdated(Err(e)) => {
                    self.busy = None;
                    self.toast(format!("SUBSCRIPTION SYNC FAIL: {e}"), false);
                }
                Msg::Ip(s) => self.ip = s,
                Msg::Ping(id, r) => {
                    self.pending.remove(&id);
                    self.pings.insert(id, r);
                    if self.sort_ping {
                        self.rebuild();
                    }
                }
                Msg::Rtt(r) => {
                    self.rtt_busy = false;
                    self.rtt = r;
                    if let Some(ms) = r {
                        push(&mut self.rtt_hist, ms as u64);
                    }
                }
                Msg::Flows(flows) => {
                    self.flows = flows;
                }
                Msg::ReconDone(res) => {
                    self.busy = None;
                    self.recon_report = Some(res);
                    self.mode = Mode::Recon;
                }
                Msg::SpeedDone(res) => {
                    self.busy = None;
                    match res {
                        Ok(res) => {
                            self.speed_result = Some(res);
                            self.speed_running = false;
                            self.mode = Mode::Speed;
                            self.toast("BENCHMARK SATURATION COMPLETE", true);
                        }
                        Err(e) => {
                            self.speed_result = None;
                            self.speed_running = false;
                            self.mode = Mode::Speed;
                            self.toast(format!("BENCHMARK FAILED: {e}"), false);
                        }
                    }
                }
            }
        }
        changed
    }

    pub(crate) fn tick(&mut self) -> bool {
        let mut changed = false;
        if self
            .toast
            .as_ref()
            .map(|t| t.2.elapsed() > Duration::from_secs(5))
            .unwrap_or(false)
        {
            self.toast = None;
            changed = true;
        }
        if self.show_flows
            && self.busy.is_none()
            && self.last_flows_tick.elapsed() >= Duration::from_millis(1500)
        {
            self.last_flows_tick = Instant::now();
            let tx = self.tx.clone();
            thread::spawn(move || {
                let flows = tunnel::active_flows();
                let _ = tx.send(Msg::Flows(flows));
            });
        }
        if self.session.is_some()
            && self.busy.is_none()
            && !self.rtt_busy
            && self.last_rtt.elapsed() >= Duration::from_secs(2)
        {
            self.rtt_busy = true;
            self.last_rtt = Instant::now();
            let tx = self.tx.clone();
            thread::spawn(move || {
                let _ = tx.send(Msg::Rtt(ping::probe()));
            });
        }
        if self.last_tick.elapsed() < Duration::from_secs(1) || self.busy.is_some() {
            return changed;
        }
        let elapsed_secs = self.last_tick.elapsed().as_secs_f64();
        self.last_tick = Instant::now();
        if self.session.is_none() {
            return changed;
        }
        changed = true;
        match tunnel::load_session() {
            None => {
                self.session = None;
                self.ip.clear();
                self.rtt = None;
                self.down_peak = 0;
                self.up_peak = 0;
                self.last = None;
                self.down.clear();
                self.up.clear();
                self.toast("TUNNEL SEVERED BY KERNEL", false);
            }
            Some(s) => {
                if let Some((rb, tb)) = tunnel::bytes(&s.iface) {
                    if let Some((lr, lt)) = self.last {
                        let d = if elapsed_secs > 0.0 {
                            ((rb.saturating_sub(lr) as f64) / elapsed_secs).round() as u64
                        } else {
                            rb.saturating_sub(lr)
                        };
                        let u = if elapsed_secs > 0.0 {
                            ((tb.saturating_sub(lt) as f64) / elapsed_secs).round() as u64
                        } else {
                            tb.saturating_sub(lt)
                        };
                        if d > self.down_peak {
                            self.down_peak = d;
                        }
                        if u > self.up_peak {
                            self.up_peak = u;
                        }
                        push(&mut self.down, d);
                        push(&mut self.up, u);
                    } else {
                        self.base = (rb, tb);
                        push(&mut self.down, 0);
                        push(&mut self.up, 0);
                    }
                    self.last = Some((rb, tb));
                } else {
                    push(&mut self.down, 0);
                    push(&mut self.up, 0);
                }
            }
        }
        changed
    }

    pub(crate) fn reconnect(&mut self) {
        if self.busy.is_some() {
            return;
        }
        if let Some(s) = &self.session {
            let sid = s.id.clone();
            if let Some(i) = self
                .view
                .iter()
                .position(|&idx| self.profiles[idx].id == sid)
            {
                self.list.select(Some(i));
            }
        }
        self.connect();
    }

    pub(crate) fn toggle_shield(&mut self) {
        let pref = shield::is_enabled_preference();
        if pref {
            shield::set_enabled_preference(false);
            let _ = shield::disarm();
            self.shield_armed = false;
            self.toast("ANTI-LEAK SHIELD DISARMED // KILL-SWITCH OFF", false);
        } else {
            shield::set_enabled_preference(true);
            if let Some(s) = &self.session {
                let endpoint_host = s.server.split(':').next().unwrap_or(&s.server);
                if let Err(e) = shield::arm(Some(&s.iface), Some(endpoint_host)) {
                    self.toast(format!("SHIELD ARM ERROR: {e}"), false);
                } else {
                    self.shield_armed = true;
                    self.toast("ANTI-LEAK SHIELD ARMED // PACKET LEAKAGE BLOCKED", true);
                }
            } else {
                self.shield_armed = false;
                self.toast("SHIELD PREFERENCE ARMED (AUTO-LOCK ON CONNECT)", true);
            }
        }
    }

    pub(crate) fn toggle_mode(&mut self) {
        let cur = vortex_core::storage::get_mode_preference();
        let next = match cur {
            OperationalMode::Tunnel => OperationalMode::Proxy,
            OperationalMode::Proxy => OperationalMode::Tunnel,
        };
        self.set_operational_mode(next);
        if self.mode == Mode::ModeSelect {
            self.mode = Mode::Normal;
        }
    }

    pub(crate) fn set_operational_mode(&mut self, mode: OperationalMode) {
        let _ = vortex_core::storage::set_mode_preference(mode);
        let client = vortex_core::ipc::IpcClient::new();
        if client.is_daemon_running() {
            let _ = client.request_sync(&vortex_core::ipc::IpcRequest::SetMode { mode });
        }
        match mode {
            OperationalMode::Tunnel => {
                self.toast("ACTIVATED: TUNNEL MODE (Whole-system VPN via vx0)", true);
            }
            OperationalMode::Proxy => {
                self.toast(
                    "ACTIVATED: PROXY MODE (Local SOCKS5/HTTP 127.0.0.1:1080 · No Root)",
                    true,
                );
            }
        }
        if self.session.is_some() {
            self.reconnect();
        }
    }

    pub fn handle_mouse(&mut self, m: MouseEvent) -> bool {
        if let MouseEventKind::Down(MouseButton::Left) = m.kind {
            match &self.mode {
                Mode::ModeSelect => {
                    if m.row >= 3 && m.row <= 7 {
                        self.set_operational_mode(OperationalMode::Tunnel);
                        self.mode = Mode::Normal;
                    } else if m.row >= 8 && m.row <= 13 {
                        self.set_operational_mode(OperationalMode::Proxy);
                        self.mode = Mode::Normal;
                    } else {
                        self.mode = Mode::Normal;
                    }
                }
                Mode::Normal if m.row <= 1 || m.row >= 23 => {
                    self.toggle_mode();
                }
                _ => {}
            }
        }
        false
    }

    /// Primary key event handler: delegates purely to keymap::map_key and apply
    pub fn handle_key(&mut self, k: KeyEvent) -> bool {
        if let Some(action) = keymap::map_key(&self.mode, k) {
            self.apply(action)
        } else {
            false
        }
    }

    pub fn apply(&mut self, action: Action) -> bool {
        match action {
            Action::ForceQuit => {
                let _ = tunnel::disconnect();
                return true;
            }
            Action::Quit => {
                if self.session.is_some() {
                    self.mode = Mode::Confirm(ConfirmKind::QuitWhileConnected);
                    return false;
                }
                return true;
            }
            Action::ConfirmYes => {
                match self.mode {
                    Mode::Confirm(ConfirmKind::DeleteNode) => {
                        self.delete();
                        self.mode = Mode::Normal;
                    }
                    Mode::Confirm(ConfirmKind::QuitWhileConnected) => {
                        let _ = tunnel::disconnect();
                        return true;
                    }
                    _ => {}
                }
                self.toast = None;
            }
            Action::ConfirmBackground => {
                if matches!(self.mode, Mode::Confirm(ConfirmKind::QuitWhileConnected)) {
                    return true;
                }
            }
            Action::ConfirmNo => {
                self.mode = Mode::Normal;
                self.toast = None;
            }
            Action::Cancel => match &self.mode {
                Mode::Normal => {
                    if self.show_log {
                        self.show_log = false;
                    } else if !self.filter.is_empty() {
                        self.filter.clear();
                        self.rebuild();
                    }
                }
                Mode::Search(_) => {
                    self.filter.clear();
                    self.rebuild();
                    self.mode = Mode::Normal;
                }
                _ => {
                    self.mode = Mode::Normal;
                    self.toast = None;
                }
            },
            Action::NextNode => {
                if self.mode == Mode::Rules {
                    let len = self.rules_cfg.custom_rules.len();
                    if len > 0 {
                        let next = self
                            .rules_list
                            .selected()
                            .map(|i| (i + 1) % len)
                            .unwrap_or(0);
                        self.rules_list.select(Some(next));
                    }
                } else {
                    self.mv(1);
                }
            }
            Action::PrevNode => {
                if self.mode == Mode::Rules {
                    let len = self.rules_cfg.custom_rules.len();
                    if len > 0 {
                        let prev = self
                            .rules_list
                            .selected()
                            .map(|i| if i == 0 { len - 1 } else { i - 1 })
                            .unwrap_or(0);
                        self.rules_list.select(Some(prev));
                    }
                } else {
                    self.mv(-1);
                }
            }
            Action::FirstNode => {
                if !self.view.is_empty() {
                    self.list.select(Some(0));
                }
            }
            Action::LastNode => {
                if !self.view.is_empty() {
                    self.list.select(Some(self.view.len() - 1));
                }
            }
            Action::FocusNextPanel => {
                self.focused_panel = (self.focused_panel % 3) + 1;
            }
            Action::FocusPanel(p) => {
                if (1..=3).contains(&p) {
                    self.focused_panel = p;
                }
            }
            Action::EnterSearch => {
                self.mode = Mode::Search(self.filter.clone());
            }
            Action::ConnectSelected => {
                let active = self.session.as_ref().map(|s| s.id.as_str());
                if active.is_some() && active == self.cur().map(|p| p.id.as_str()) {
                    self.toast("already connected — space to disconnect", false);
                } else {
                    self.connect();
                }
            }
            Action::ToggleConnection => {
                if self.session.is_some() {
                    self.disconnect();
                } else {
                    self.connect();
                }
            }
            Action::Reconnect => self.reconnect(),
            Action::ToggleShield => self.toggle_shield(),
            Action::ToggleMode => self.toggle_mode(),
            Action::OpenModeSelect => {
                self.mode = Mode::ModeSelect;
            }
            Action::SetModeTunnel => {
                self.set_operational_mode(OperationalMode::Tunnel);
                self.mode = Mode::Normal;
            }
            Action::SetModeProxy => {
                self.set_operational_mode(OperationalMode::Proxy);
                self.mode = Mode::Normal;
            }
            Action::AddNode => {
                self.mode = Mode::Add(String::new());
            }
            Action::EditNode => {
                if let Some(p) = self.cur() {
                    self.mode = Mode::Edit(p.name.clone());
                }
            }
            Action::DeleteNode => {
                if let Some(p) = self.cur() {
                    let m = format!("PURGE TARGET [{}]?  PRESS [Y] TO CONFIRM", p.name);
                    self.mode = Mode::Confirm(ConfirmKind::DeleteNode);
                    self.toast = Some((m, false, Instant::now() + Duration::from_secs(600)));
                }
            }
            Action::CopyConfig => {
                if self.mode == Mode::Qr {
                    if let Some(p) = &self.qr_profile {
                        match store::copy_to_clipboard(&p.data) {
                            Ok(()) => self.toast("PAYLOAD COPIED TO SYSTEM CLIPBOARD", true),
                            Err(e) => self.toast(format!("CLIPBOARD COPY FAILED: {e}"), false),
                        }
                    }
                } else if let Some(p) = self.cur() {
                    match store::copy_to_clipboard(&p.data) {
                        Ok(()) => self.toast("PAYLOAD COPIED TO SYSTEM CLIPBOARD", true),
                        Err(e) => self.toast(format!("CLIPBOARD COPY FAILED: {e}"), false),
                    }
                }
            }
            Action::ShowQr => {
                if let Some(p) = self.cur().cloned() {
                    let qr = store::generate_qr(&p.data).map_err(|e| format!("{e}"));
                    self.qr_profile = Some(p);
                    self.qr_code = Some(qr);
                    self.qr_exported = None;
                    self.mode = Mode::Qr;
                }
            }
            Action::CycleSort => {
                self.sort_mode = match self.sort_mode {
                    SortMode::Name => SortMode::Latency,
                    SortMode::Latency => SortMode::Transport,
                    SortMode::Transport => SortMode::Name,
                };
                self.sort_ping = self.sort_mode == SortMode::Latency;
                self.rebuild();
                self.toast(
                    match self.sort_mode {
                        SortMode::Latency => "sorted by latency",
                        SortMode::Transport => "sorted by transport",
                        SortMode::Name => "sorted by name",
                    },
                    true,
                );
            }
            Action::CycleTransportFilter => {
                if self.show_flows {
                    self.flows_filter = self.flows_filter.cycle();
                    self.toast(format!("flows filter: {}", self.flows_filter.label()), true);
                } else {
                    self.transport_filter = self.transport_filter.cycle();
                    self.rebuild();
                    self.toast(
                        format!("transport filter: {}", self.transport_filter.label()),
                        true,
                    );
                }
            }
            Action::TestSelected => self.test(true),
            Action::TestAll => self.test(false),
            Action::SpeedTest => {
                self.start("speed benchmark");
                self.toast("LAUNCHING BANDWIDTH BENCHMARK (MULTI-STREAM)...", true);
                self.speed_result = None;
                self.speed_running = true;
                self.mode = Mode::Speed;
                let tx = self.tx.clone();
                thread::spawn(move || {
                    let res = benchmark::run_speed_test(benchmark::DEFAULT_TEST_DURATION_SECS)
                        .map_err(|e| format!("{e:#}"));
                    let _ = tx.send(Msg::SpeedDone(res));
                });
            }
            Action::UpdateSubs => self.sync_subs(),
            Action::ManageSubs => {
                self.subs = store::load_subs();
                self.subs_list = ListState::default();
                if !self.subs.is_empty() {
                    self.subs_list.select(Some(0));
                }
                self.mode = Mode::Subs;
            }
            Action::ManageRules => {
                self.rules_cfg = vortex_core::routing::RulesConfig::load();
                self.rules_list = ListState::default();
                if !self.rules_cfg.custom_rules.is_empty() {
                    self.rules_list.select(Some(0));
                }
                self.mode = Mode::Rules;
            }
            Action::ToggleRule => {
                if let Some(idx) = self.rules_list.selected() {
                    if idx < self.rules_cfg.custom_rules.len() {
                        self.rules_cfg.custom_rules[idx].enabled =
                            !self.rules_cfg.custom_rules[idx].enabled;
                        let _ = self.rules_cfg.save();
                        self.toast("ROUTING RULE STATUS TOGGLED", true);
                    }
                }
            }
            Action::ToggleFlows => {
                self.show_flows = !self.show_flows;
                if self.show_flows {
                    self.flows = tunnel::active_flows();
                    self.toast(
                        format!(
                            "FLOW SNIFFER ENGAGED // {} ACTIVE SOCKET(S)",
                            self.flows.len()
                        ),
                        true,
                    );
                } else {
                    self.toast("FLOW SNIFFER DISENGAGED", true);
                }
            }
            Action::ToggleLog => self.show_log = !self.show_log,
            Action::ShowIpInfo => {
                if let Some(p) = self.cur().cloned() {
                    self.start("reconnaissance probe");
                    self.toast(format!("LAUNCHING DEEP RECON // TARGET: {}", p.name), true);
                    let tx = self.tx.clone();
                    thread::spawn(move || {
                        let r = recon::probe_recon(&p).map_err(|e| format!("{e:#}"));
                        let _ = tx.send(Msg::ReconDone(r));
                    });
                } else {
                    self.toast("SELECT A TARGET NODE FIRST", false);
                }
            }
            Action::Help => self.mode = Mode::Help,
            Action::ManageAuth => self.manage_auth(),
            Action::PasteClipboard => self.paste_clip(),
            Action::InputChar(c) => match &mut self.mode {
                Mode::Search(s) => {
                    s.push(c);
                    self.filter = s.clone();
                    self.rebuild();
                }
                Mode::Add(s) | Mode::Edit(s) => {
                    s.push(c);
                }
                _ => {}
            },
            Action::Backspace => match &mut self.mode {
                Mode::Search(s) => {
                    s.pop();
                    self.filter = s.clone();
                    self.rebuild();
                }
                Mode::Add(s) | Mode::Edit(s) => {
                    s.pop();
                }
                _ => {}
            },
            Action::ClearInput => match &mut self.mode {
                Mode::Search(s) => {
                    s.clear();
                    self.filter.clear();
                    self.rebuild();
                }
                Mode::Add(s) | Mode::Edit(s) => {
                    s.clear();
                }
                _ => {}
            },
            Action::Submit => match std::mem::replace(&mut self.mode, Mode::Normal) {
                Mode::Search(_) => {}
                Mode::Add(s) => {
                    if !s.trim().is_empty() {
                        self.import(s);
                    }
                }
                Mode::Edit(s) => {
                    self.rename(s);
                }
                _ => {}
            },
            Action::ExportConfig => {
                if let Some(p) = &self.qr_profile {
                    match store::export_to_file(p) {
                        Ok(path) => {
                            let p_str = path.display().to_string();
                            self.toast(format!("EXPORTED TO {p_str}"), true);
                            self.qr_exported = Some(p_str);
                        }
                        Err(e) => self.toast(format!("EXPORT FAILED: {e}"), false),
                    }
                }
            }
            Action::NextSub => {
                let n = self.subs.len();
                if n > 0 {
                    let cur = self.subs_list.selected().unwrap_or(0);
                    self.subs_list.select(Some((cur + 1).rem_euclid(n)));
                }
            }
            Action::PrevSub => {
                let n = self.subs.len();
                if n > 0 {
                    let cur = self.subs_list.selected().unwrap_or(0) as i32;
                    self.subs_list
                        .select(Some((cur - 1).rem_euclid(n as i32) as usize));
                }
            }
            Action::SyncSelectedSub => {
                if let Some(i) = self.subs_list.selected().and_then(|i| self.subs.get(i)) {
                    let id = i.id.clone();
                    self.sync_single_sub(id);
                }
            }
            Action::DeleteSub => {
                if let Some(i) = self.subs_list.selected() {
                    if i < self.subs.len() {
                        let sub = self.subs.remove(i);
                        let _ = store::remove_sub(&sub.id, true);
                        self.reload();
                        if !self.subs.is_empty() {
                            self.subs_list.select(Some(i.min(self.subs.len() - 1)));
                        } else {
                            self.subs_list.select(None);
                        }
                        self.toast(format!("PURGED SUBSCRIPTION [{}]", sub.name), true);
                    }
                }
            }
            Action::RetryProbe => {
                if let Some(p) = self.cur().cloned() {
                    self.start("reconnaissance probe");
                    self.toast(format!("RE-PROBING NODE // TARGET: {}", p.name), true);
                    let tx = self.tx.clone();
                    thread::spawn(move || {
                        let r = recon::probe_recon(&p).map_err(|e| format!("{e:#}"));
                        let _ = tx.send(Msg::ReconDone(r));
                    });
                }
            }
            Action::RetrySpeedTest => {
                if !self.speed_running {
                    self.start("speed benchmark");
                    self.toast("INITIATING MULTI-STREAM SPEED BENCHMARK...", true);
                    self.speed_result = None;
                    self.speed_running = true;
                    let tx = self.tx.clone();
                    thread::spawn(move || {
                        let res = benchmark::run_speed_test(benchmark::DEFAULT_TEST_DURATION_SECS)
                            .map_err(|e| format!("{e:#}"));
                        let _ = tx.send(Msg::SpeedDone(res));
                    });
                }
            }
        }
        false
    }
}

// ───────────────────────── entry ─────────────────────────


pub fn run() -> Result<()> {
    enable_raw_mode()?;
    execute!(
        stdout(),
        EnterAlternateScreen,
        EnableBracketedPaste,
        EnableMouseCapture
    )?;
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |i| {
        let _ = tunnel::disconnect();
        let _ = restore();
        default_hook(i);
    }));

    extern "C" fn sig_cleanup(_: libc::c_int) {
        let _ = tunnel::disconnect();
        let _ = restore();
        unsafe {
            libc::_exit(130);
        }
    }
    unsafe {
        libc::signal(libc::SIGINT, sig_cleanup as *const () as usize);
        libc::signal(libc::SIGTERM, sig_cleanup as *const () as usize);
        libc::signal(libc::SIGHUP, sig_cleanup as *const () as usize);
    }
    let mut term = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut app = App::new();
    let res = (|| -> Result<()> {
        let mut dirty = true;
        loop {
            if dirty {
                term.draw(|f| draw(f, &mut app))?;
                dirty = false;
            }
            let is_animating = app.busy.is_some() || !app.pending.is_empty();
            let timeout = if is_animating {
                Duration::from_millis(90)
            } else {
                Duration::from_millis(250)
            };
            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(k) => {
                        if app.handle_key(k) {
                            break;
                        }
                        dirty = true;
                    }
                    Event::Mouse(m) => {
                        if app.handle_mouse(m) {
                            break;
                        }
                        dirty = true;
                    }
                    Event::Paste(s) => {
                        app.paste(s);
                        dirty = true;
                    }
                    Event::Resize(_, _) => {
                        dirty = true;
                    }
                    _ => {}
                }
            }
            if app.drain() {
                dirty = true;
            }
            if app.tick() {
                dirty = true;
            }
            if is_animating {
                dirty = true;
            }
        }
        Ok(())
    })();
    restore()?;
    if let Some(s) = tunnel::load_session() {
        println!(
            "tunnel still running: {} — `vortex down` to stop it",
            s.name
        );
    }
    res
}


pub(crate) fn restore() -> Result<()> {
    disable_raw_mode()?;
    execute!(
        stdout(),
        LeaveAlternateScreen,
        DisableBracketedPaste,
        DisableMouseCapture
    )?;
    Ok(())
}

// ───────────────────────── drawing ─────────────────────────


pub(crate) fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let header_h = if area.height >= 12 { 2 } else { 1 };
    let footer_h = if area.height >= 6 { 1 } else { 0 };
    let rows = Layout::vertical([
        Constraint::Length(header_h),
        Constraint::Min(3),
        Constraint::Length(footer_h),
    ])
    .split(area);

    header(f, rows[0], app);
    if area.width >= 84 {
        let cols = Layout::horizontal([Constraint::Percentage(44), Constraint::Percentage(56)])
            .split(rows[1]);
        profiles(f, cols[0], app);
        info(f, cols[1], app);
    } else if app.show_log {
        info(f, rows[1], app);
    } else {
        profiles(f, rows[1], app);
    }
    if footer_h > 0 {
        footer(f, rows[2], app);
    }
    let mode = app.mode.clone();
    match &mode {
        Mode::Add(s) => popup(
            f,
            area,
            "0xIN // INJECT CONFIGURATION PAYLOAD",
            "VLESS · VMESS · TROJAN · SS · HY2 · TUIC · WG · AWG · OVPN · SUB URL",
            s,
        ),
        Mode::Edit(s) => popup(
            f,
            area,
            "0xRN // MUTATE TARGET IDENTIFIER",
            "enter new cryptographic profile alias",
            s,
        ),
        Mode::Confirm(kind) => confirm_popup(f, area, app, *kind),
        Mode::Help => help(f, area),
        Mode::Qr => {
            if let Some(p) = &app.qr_profile {
                if let Some(qr) = &app.qr_code {
                    qr_popup(f, area, p, qr, app.qr_exported.as_deref());
                }
            }
        }
        Mode::Subs => subs_popup(f, area, &mut app.subs_list, &app.subs),
        Mode::Recon => {
            if let Some(res) = &app.recon_report {
                recon_popup(f, area, res);
            }
        }
        Mode::Speed => speed_popup(f, area, app.speed_result.as_ref(), app.speed_running),
        Mode::Rules => rules_popup(f, area, &app.rules_cfg, &mut app.rules_list),
        Mode::ModeSelect => mode_select_popup(f, area),
        _ => {}
    }
}


pub(crate) fn footer(f: &mut Frame, a: Rect, app: &App) {
    if a.height == 0 {
        return;
    }
    if let Some((m, ok, _)) = &app.toast {
        let (tag, c) = if *ok {
            (" [✔ SYSTEM OK] >> ", GREEN)
        } else {
            (" [✕ ALERT / ERROR] >> ", RED)
        };
        let text = format!("{tag}{}", trunc(m, (a.width as usize).saturating_sub(25)));
        f.render_widget(
            Paragraph::new(Span::styled(text, Style::new().fg(c).bold())),
            a,
        );
        return;
    }
    match &app.mode {
        Mode::Search(q) => {
            let line = Line::from(vec![
                Span::styled(" [SEARCH] ", Style::new().fg(GREEN).bold()),
                Span::styled(format!("\"{}\"█  ", q), Style::new().fg(FG).bold()),
                Span::styled("[Enter]", Style::new().fg(CYAN).bold()),
                Span::styled(" keep filter  ", Style::new().fg(FG_DIM)),
                Span::styled("[Esc]", Style::new().fg(CYAN).bold()),
                Span::styled(" clear & exit", Style::new().fg(FG_DIM)),
            ]);
            f.render_widget(Paragraph::new(line), a);
        }
        Mode::Confirm(ConfirmKind::DeleteNode) => {
            let line = Line::from(vec![
                Span::styled(" [CONFIRM PURGE] >> ", Style::new().fg(RED).bold()),
                Span::styled("[y]", Style::new().fg(GREEN).bold()),
                Span::styled(" delete node  ", Style::new().fg(FG_DIM)),
                Span::styled("[n/Esc]", Style::new().fg(RED).bold()),
                Span::styled(" cancel", Style::new().fg(FG_DIM)),
            ]);
            f.render_widget(Paragraph::new(line), a);
        }
        Mode::Confirm(ConfirmKind::QuitWhileConnected) => {
            let line = Line::from(vec![
                Span::styled(" [ACTIVE TUNNEL] >> ", Style::new().fg(YELLOW).bold()),
                Span::styled("[y]", Style::new().fg(GREEN).bold()),
                Span::styled(" disconnect & quit  ", Style::new().fg(FG_DIM)),
                Span::styled("[b]", Style::new().fg(PURPLE).bold()),
                Span::styled(" quit (background)  ", Style::new().fg(FG_DIM)),
                Span::styled("[n/Esc]", Style::new().fg(RED).bold()),
                Span::styled(" cancel", Style::new().fg(FG_DIM)),
            ]);
            f.render_widget(Paragraph::new(line), a);
        }
        _ => {
            let is_connected = app.session.is_some();
            let shield_armed = app.shield_armed || shield::is_armed();
            let cur_mode = vortex_core::storage::get_mode_preference();

            let space_desc = if is_connected {
                "disconnect"
            } else {
                "connect"
            };
            let shield_desc = if shield_armed {
                "shield:armed"
            } else {
                "shield:off"
            };
            let (mode_btn_txt, mode_btn_color) = match cur_mode {
                OperationalMode::Tunnel => ("TUNNEL⇄proxy", CYAN),
                OperationalMode::Proxy => ("PROXY⇄tunnel", YELLOW),
            };

            let hints: [(&str, &str); 10] = [
                ("Enter", "connect"),
                ("Space", space_desc),
                ("m", mode_btn_txt),
                ("M", "modes"),
                ("t", "test"),
                ("p", "filter"),
                ("a", "add"),
                ("K", shield_desc),
                ("?", "help"),
                ("q", "quit"),
            ];

            let (prompt_user, prompt_bracket, prompt_sym) = match cur_mode {
                OperationalMode::Tunnel => (" root@vortex", "[TUN]# ", CYAN),
                OperationalMode::Proxy => (" user@vortex", "[PROXY]$ ", YELLOW),
            };
            let mut spans = vec![
                Span::styled(prompt_user, Style::new().fg(GREEN).bold()),
                Span::styled(prompt_bracket, Style::new().fg(prompt_sym).bold()),
            ];
            for (k, d) in hints {
                if k == "m" {
                    spans.push(Span::styled(
                        format!("[{k}]"),
                        Style::new().fg(BLACK).bg(mode_btn_color).bold(),
                    ));
                    spans.push(Span::styled(
                        format!(" {d}  "),
                        Style::new().fg(mode_btn_color).bold(),
                    ));
                } else {
                    spans.push(Span::styled(format!("[{k}]"), Style::new().fg(CYAN).bold()));
                    spans.push(Span::styled(format!(" {d}  "), Style::new().fg(FG_DIM)));
                }
            }
            f.render_widget(Paragraph::new(Line::from(spans)), a);
        }
    }
}

