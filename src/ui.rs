use crate::ping::{self, Ping};
use crate::store::{self, Kind, Profile};
use crate::tunnel::{self, Session};
use anyhow::Result;
use crossterm::{
    event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{prelude::*, widgets::*};
use std::{
    borrow::Cow,
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

// Elite Black-Hat Cyber Palette
const FG: Color = Color::Rgb(0xd2, 0xf7, 0xee);         // Phosphor Ice-White
const FG_DIM: Color = Color::Rgb(0x60, 0x8a, 0x8e);     // Tactical Cyan-Gray
const DIM: Color = Color::Rgb(0x2a, 0x46, 0x4c);        // Dark Matrix Dim
const CYAN: Color = Color::Rgb(0x00, 0xf0, 0xff);       // Electric Cyan
const PURPLE: Color = Color::Rgb(0xbd, 0x42, 0xff);     // Plasma Violet
const BLUE: Color = Color::Rgb(0x2d, 0x9c, 0xff);       // Cobalt Blue
const GREEN: Color = Color::Rgb(0x00, 0xff, 0x66);      // Neon Lime Phosphor
const YELLOW: Color = Color::Rgb(0xff, 0xb8, 0x00);     // Amber Warning
const RED: Color = Color::Rgb(0xff, 0x22, 0x55);        // Breach Red
const BORDER: Color = Color::Rgb(0x16, 0x3d, 0x44);     // Deep Cyber Teal Border
const BORDER_ACTIVE: Color = Color::Rgb(0x00, 0xf0, 0xff); // Active Cyan Frame
const SEL_BG: Color = Color::Rgb(0x0a, 0x26, 0x2c);     // Tactical Selection Glow
const SEL_FG: Color = Color::Rgb(0x00, 0xff, 0xcc);     // Highlight Active
const SPIN: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const HIST: usize = 240;

enum Msg {
    Connected(Result<Session, String>),
    Disconnected(Result<(), String>),
    Imported(Result<usize, String>),
    SubsUpdated(Result<usize, String>),
    Ip(String),
    Ping(String, Ping),
    Rtt(Option<u32>),
}

enum Mode {
    Normal,
    Add(String),
    Filter(String),
    Rename(String),
    Confirm,
    Help,
    Qr {
        profile: Profile,
        qr: Result<String, String>,
        exported: Option<String>,
    },
    Subs {
        list: ListState,
        subs: Vec<store::Subscription>,
    },
}

struct App {
    profiles: Vec<Profile>,
    /// indices into `profiles` after filter + sort
    view: Vec<usize>,
    list: ListState,
    filter: String,
    sort_ping: bool,
    mode: Mode,
    session: Option<Session>,
    busy: Option<&'static str>,
    busy_since: Instant,
    toast: Option<(String, bool, Instant)>,
    show_log: bool,
    down: Vec<u64>,
    up: Vec<u64>,
    down_peak: u64,
    up_peak: u64,
    rtt_hist: Vec<u64>,
    rtt: Option<u32>,
    rtt_busy: bool,
    last_rtt: Instant,
    last: Option<(u64, u64)>,
    base: (u64, u64),
    last_tick: Instant,
    ip: String,
    pings: HashMap<String, Ping>,
    pending: HashSet<String>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

fn push(v: &mut Vec<u64>, x: u64) {
    v.push(x);
    if v.len() > HIST {
        v.remove(0);
    }
}

/// shared text-editing keys for the single-line inputs; returns true if the key was consumed
fn edit(s: &mut String, k: &KeyEvent) -> bool {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    match k.code {
        KeyCode::Backspace => {
            s.pop();
            true
        }
        KeyCode::Char('u') if ctrl => {
            s.clear();
            true
        }
        KeyCode::Char('w') if ctrl => {
            let t = s.trim_end().len();
            s.truncate(t);
            while s.chars().last().map(|c| !c.is_whitespace()).unwrap_or(false) {
                s.pop();
            }
            true
        }
        KeyCode::Char(c) if !ctrl => {
            s.push(c);
            true
        }
        _ => false,
    }
}

impl App {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let mut a = App {
            profiles: store::load_all(),
            view: vec![],
            list: ListState::default(),
            filter: String::new(),
            sort_ping: false,
            mode: Mode::Normal,
            session: tunnel::load_session(),
            busy: None,
            busy_since: Instant::now(),
            toast: None,
            show_log: false,
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
            tx,
            rx,
        };
        a.rebuild();
        // start on the active profile, else the one used last time
        let want = a.session.as_ref().map(|s| s.id.clone()).or_else(store::last);
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
        }
        a
    }

    fn cur(&self) -> Option<&Profile> {
        self.view.get(self.list.selected()?).map(|&i| &self.profiles[i])
    }

    fn toast(&mut self, m: impl Into<String>, ok: bool) {
        self.toast = Some((m.into(), ok, Instant::now()));
    }

    fn rebuild(&mut self) {
        let keep = self.cur().map(|p| p.id.clone());
        let f = self.filter.to_lowercase();
        let mut v: Vec<usize> = (0..self.profiles.len())
            .filter(|&i| {
                let p = &self.profiles[i];
                f.is_empty()
                    || p.name.to_lowercase().contains(&f)
                    || p.kind.tag().to_lowercase().contains(&f)
                    || p.server.to_lowercase().contains(&f)
            })
            .collect();
        if self.sort_ping {
            v.sort_by_key(|&i| match self.pings.get(&self.profiles[i].id) {
                Some(Ping::Ms(m)) => (0, *m),
                None => (1, 0),
                Some(Ping::Timeout) => (2, 0),
            });
        }
        self.view = v;
        let idx = keep.and_then(|id| self.view.iter().position(|&i| self.profiles[i].id == id)).unwrap_or(0);
        self.list.select(if self.view.is_empty() { None } else { Some(idx.min(self.view.len() - 1)) });
    }

    fn reload(&mut self) {
        self.profiles = store::load_all();
        self.pings.retain(|id, _| self.profiles.iter().any(|p| &p.id == id));
        self.rebuild();
    }

    fn start(&mut self, what: &'static str) {
        self.busy = Some(what);
        self.busy_since = Instant::now();
    }

    fn spawn_ip(&self) {
        let tx = self.tx.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(1200));
            let _ = tx.send(Msg::Ip(tunnel::public_ip()));
        });
    }

    /// latency-test the visible profiles (or just the selected one)
    fn test(&mut self, only_selected: bool) {
        if self.session.is_some() {
            return self.toast("disconnect first — server latency can't be measured through the tunnel", false);
        }
        let jobs: Vec<Profile> = if only_selected {
            self.cur().cloned().into_iter().collect()
        } else {
            self.view.iter().map(|&i| self.profiles[i].clone()).collect()
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

    fn connect(&mut self) {
        if self.busy.is_some() {
            return;
        }
        let Some(mut p) = self.cur().cloned() else { return };
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
        self.start("connecting");
        self.ip.clear();
        let tx = self.tx.clone();
        thread::spawn(move || {
            let r = tunnel::connect_with_credentials(&p, creds.as_ref().map(|(u, pw)| (u.as_str(), pw.as_str())))
                .map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::Connected(r));
        });
    }

    fn manage_auth(&mut self) {
        let Some(mut p) = self.cur().cloned() else { return };
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

    fn disconnect(&mut self) {
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

    fn import(&mut self, s: String) {
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

    fn delete(&mut self) {
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

    fn rename(&mut self, name: String) {
        let Some(id) = self.cur().map(|p| p.id.clone()) else { return };
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

    fn sync_subs(&mut self) {
        if self.busy.is_some() {
            return;
        }
        self.start("syncing subscriptions");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let r = store::update_all_subs().map(|results| {
                let total: usize = results.iter().filter_map(|(_, r)| r.as_ref().ok()).sum();
                total
            }).map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::SubsUpdated(r));
        });
    }

    fn sync_single_sub(&mut self, id: String) {
        if self.busy.is_some() {
            return;
        }
        self.start("updating sub");
        let tx = self.tx.clone();
        thread::spawn(move || {
            let r = store::update_sub(&id).map(|(_, count)| count).map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::SubsUpdated(r));
        });
    }

    fn paste_clip(&mut self) {
        let get_text = || -> Option<String> {
            if let Ok(u) = std::env::var("SUDO_USER") {
                if !u.is_empty() && u != "root" {
                    if let Ok(o) = Command::new("sudo").args(["-u", &u, "wl-paste", "-n"]).output() {
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
    fn paste(&mut self, s: String) {
        match &mut self.mode {
            Mode::Add(i) | Mode::Rename(i) => i.push_str(s.trim()),
            Mode::Filter(i) => {
                i.push_str(s.trim());
                self.filter = i.clone();
                self.rebuild();
            }
            Mode::Normal => self.import(s),
            _ => {}
        }
    }

    fn mv(&mut self, d: i32) {
        let n = self.view.len() as i32;
        if n > 0 {
            let cur = self.list.selected().unwrap_or(0) as i32;
            self.list.select(Some((cur + d).rem_euclid(n) as usize));
        }
    }

    fn drain(&mut self) -> bool {
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
                    self.toast(format!("BREACH/AUTH FAIL: {e}"), false);
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
            }
        }
        changed
    }

    fn tick(&mut self) -> bool {
        let mut changed = false;
        if self.toast.as_ref().map(|t| t.2.elapsed() > Duration::from_secs(5)).unwrap_or(false) {
            self.toast = None;
            changed = true;
        }
        if self.session.is_some() && self.busy.is_none() && !self.rtt_busy && self.last_rtt.elapsed() >= Duration::from_secs(2) {
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
                self.toast("TUNNEL SEVERED BY KERNEL", false);
            }
            Some(s) => {
                if let Some((rb, tb)) = tunnel::bytes(&s.iface) {
                    if let Some((lr, lt)) = self.last {
                        let d = rb.saturating_sub(lr);
                        let u = tb.saturating_sub(lt);
                        if d > self.down_peak {
                            self.down_peak = d;
                        }
                        if u > self.up_peak {
                            self.up_peak = u;
                        }
                        push(&mut self.down, d);
                        push(&mut self.up, u);
                    }
                    self.last = Some((rb, tb));
                }
            }
        }
        changed
    }

    /// returns true to quit
    fn key(&mut self, k: KeyEvent) -> bool {
        use KeyCode::*;
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == Char('c') {
            return true;
        }
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Add(mut s) => {
                match k.code {
                    Esc => {}
                    Enter => {
                        if !s.trim().is_empty() {
                            self.import(s);
                        }
                    }
                    _ => {
                        edit(&mut s, &k);
                        self.mode = Mode::Add(s);
                    }
                }
                return false;
            }
            Mode::Rename(mut s) => {
                match k.code {
                    Esc => {}
                    Enter => self.rename(s),
                    _ => {
                        edit(&mut s, &k);
                        self.mode = Mode::Rename(s);
                    }
                }
                return false;
            }
            Mode::Filter(mut s) => {
                match k.code {
                    Esc => {
                        self.filter.clear();
                        self.rebuild();
                    }
                    Enter => {}
                    _ => {
                        if edit(&mut s, &k) {
                            self.filter = s.clone();
                            self.rebuild();
                        }
                        self.mode = Mode::Filter(s);
                    }
                }
                return false;
            }
            Mode::Confirm => {
                self.toast = None;
                if k.code == Char('y') || k.code == Char('Y') {
                    self.delete();
                }
                return false;
            }
            Mode::Help => return false,
            Mode::Qr { profile, qr, mut exported } => {
                match k.code {
                    Esc | Char('q') => {}
                    Char('c') | Char('C') | Char('y') => {
                        match store::copy_to_clipboard(&profile.data) {
                            Ok(()) => self.toast("PAYLOAD COPIED TO SYSTEM CLIPBOARD", true),
                            Err(e) => self.toast(format!("CLIPBOARD COPY FAILED: {e}"), false),
                        }
                        self.mode = Mode::Qr { profile, qr, exported };
                    }
                    Char('s') | Char('S') | Char('e') => {
                        match store::export_to_file(&profile) {
                            Ok(path) => {
                                let p_str = path.display().to_string();
                                self.toast(format!("EXPORTED TO {p_str}"), true);
                                exported = Some(p_str);
                            }
                            Err(e) => self.toast(format!("EXPORT FAILED: {e}"), false),
                        }
                        self.mode = Mode::Qr { profile, qr, exported };
                    }
                    _ => {
                        self.mode = Mode::Qr { profile, qr, exported };
                    }
                }
                return false;
            }
            Mode::Subs { mut list, mut subs } => {
                match k.code {
                    Esc | Char('q') => {}
                    Char('j') | Down => {
                        let n = subs.len();
                        if n > 0 {
                            let cur = list.selected().unwrap_or(0);
                            list.select(Some((cur + 1).rem_euclid(n)));
                        }
                        self.mode = Mode::Subs { list, subs };
                    }
                    Char('k') | Up => {
                        let n = subs.len();
                        if n > 0 {
                            let cur = list.selected().unwrap_or(0) as i32;
                            list.select(Some((cur - 1).rem_euclid(n as i32) as usize));
                        }
                        self.mode = Mode::Subs { list, subs };
                    }
                    Enter | Char('u') => {
                        if let Some(i) = list.selected().and_then(|i| subs.get(i)) {
                            let id = i.id.clone();
                            self.sync_single_sub(id);
                        }
                    }
                    Char('s') | Char('S') => {
                        self.sync_subs();
                    }
                    Char('a') => {
                        self.mode = Mode::Add(String::new());
                    }
                    Char('d') => {
                        if let Some(i) = list.selected() {
                            if i < subs.len() {
                                let sub = subs.remove(i);
                                let _ = store::remove_sub(&sub.id, true);
                                self.reload();
                                if !subs.is_empty() {
                                    list.select(Some(i.min(subs.len() - 1)));
                                } else {
                                    list.select(None);
                                }
                                self.toast(format!("PURGED SUBSCRIPTION [{}]", sub.name), true);
                            }
                        }
                        self.mode = Mode::Subs { list, subs };
                    }
                    _ => {
                        self.mode = Mode::Subs { list, subs };
                    }
                }
                return false;
            }
            Mode::Normal => {}
        }
        match k.code {
            Char('q') => return true,
            Char('Q') => {
                let _ = tunnel::disconnect();
                return true;
            }
            Esc => {
                if self.show_log {
                    self.show_log = false;
                } else if !self.filter.is_empty() {
                    self.filter.clear();
                    self.rebuild();
                }
            }
            Char('?') => self.mode = Mode::Help,
            Char('j') | Down => self.mv(1),
            Char('k') | Up => self.mv(-1),
            Char('g') | Home => {
                if !self.view.is_empty() {
                    self.list.select(Some(0))
                }
            }
            Char('G') | End => {
                if !self.view.is_empty() {
                    self.list.select(Some(self.view.len() - 1))
                }
            }
            Enter => {
                let active = self.session.as_ref().map(|s| s.id.as_str());
                if active.is_some() && active == self.cur().map(|p| p.id.as_str()) {
                    self.toast("already connected — space to disconnect", false);
                } else {
                    self.connect();
                }
            }
            Char(' ') | Char('s') => self.disconnect(),
            Char('S') => self.sync_subs(),
            Char('a') => self.mode = Mode::Add(String::new()),
            Char('c') | Char('C') => {
                if let Some(p) = self.cur().cloned() {
                    let qr = store::generate_qr(&p.data).map_err(|e| format!("{e}"));
                    self.mode = Mode::Qr { profile: p, qr, exported: None };
                }
            }
            Char('b') | Char('B') => {
                let subs = store::load_subs();
                let mut list = ListState::default();
                if !subs.is_empty() {
                    list.select(Some(0));
                }
                self.mode = Mode::Subs { list, subs };
            }
            Char('u') => self.manage_auth(),
            Char('v') => self.paste_clip(),
            Char('/') => self.mode = Mode::Filter(self.filter.clone()),
            Char('r') => {
                if let Some(p) = self.cur() {
                    self.mode = Mode::Rename(p.name.clone());
                }
            }
            Char('d') => {
                if let Some(p) = self.cur() {
                    let m = format!("PURGE TARGET [{}]?  PRESS [Y] TO CONFIRM", p.name);
                    self.mode = Mode::Confirm;
                    self.toast = Some((m, false, Instant::now() + Duration::from_secs(600)));
                }
            }
            Char('t') => self.test(false),
            Char('T') => self.test(true),
            Char('o') => {
                self.sort_ping = !self.sort_ping;
                self.rebuild();
                self.toast(if self.sort_ping { "sorted by latency" } else { "sorted by name" }, true);
            }
            Char('l') => self.show_log = !self.show_log,
            Char('i') => {
                if self.session.is_some() {
                    self.ip.clear();
                    self.spawn_ip();
                }
            }
            _ => {}
        }
        false
    }
}

// ───────────────────────── entry ─────────────────────────

pub fn run() -> Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |i| {
        let _ = restore();
        default_hook(i);
    }));
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
                    Event::Key(k) if k.kind == KeyEventKind::Press => {
                        if app.key(k) {
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
        println!("tunnel still running: {} — `vortex down` to stop it", s.name);
    }
    res
}

fn restore() -> Result<()> {
    disable_raw_mode()?;
    execute!(stdout(), LeaveAlternateScreen, DisableBracketedPaste)?;
    Ok(())
}

// ───────────────────────── drawing ─────────────────────────

fn fmt_bytes(b: u64) -> String {
    const U: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < 3 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn fmt_dur(s: u64) -> String {
    format!("{:02}:{:02}:{:02}", s / 3600, s % 3600 / 60, s % 60)
}

fn kind_color(k: Kind) -> Color {
    match k {
        Kind::Vless => CYAN,
        Kind::Vmess => Color::Rgb(0x00, 0xdf, 0xa2), // Mint Green
        Kind::Trojan => BLUE,
        Kind::Hy2 => PURPLE,
        Kind::Tuic => Color::Rgb(0xd9, 0x46, 0xef), // Fuchsia
        Kind::Ss => Color::Rgb(0x06, 0xb6, 0xd4),    // Electric Teal
        Kind::Wg => GREEN,
        Kind::Awg => Color::Rgb(0x10, 0xb9, 0x81),  // Emerald
        Kind::Ovpn => YELLOW,
    }
}

fn kind_badge(k: Kind) -> &'static str {
    match k {
        Kind::Vless => "VLESS",
        Kind::Vmess => "VMESS",
        Kind::Trojan => "TROJN",
        Kind::Ss => "SS-AE",
        Kind::Hy2 => "HYST2",
        Kind::Tuic => "TUIC ",
        Kind::Wg => "WG-0 ",
        Kind::Awg => "AMN-W",
        Kind::Ovpn => "OVPN ",
    }
}

fn ms_color(ms: u32) -> Color {
    if ms < 60 {
        GREEN
    } else if ms < 120 {
        CYAN
    } else if ms < 250 {
        YELLOW
    } else {
        RED
    }
}

const SPACES: &str = "                                                                                                                        ";

fn spaces(n: usize) -> &'static str {
    &SPACES[..n.min(SPACES.len())]
}

fn trunc<'a>(s: &'a str, n: usize) -> Cow<'a, str> {
    if s.chars().count() <= n {
        Cow::Borrowed(s)
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        Cow::Owned(out)
    }
}

fn block(title: &str, active: bool) -> Block<'static> {
    let border_color = if active { BORDER_ACTIVE } else { BORDER };
    Block::bordered()
        .border_type(BorderType::Plain)
        .border_style(Style::new().fg(border_color))
        .title(Line::from(vec![
            Span::styled(" ◈ [ ", Style::new().fg(border_color)),
            Span::styled(title.to_string(), Style::new().fg(if active { CYAN } else { FG }).bold()),
            Span::styled(" ] ", Style::new().fg(border_color)),
        ]))
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let header_h = if area.height >= 26 {
        2
    } else if area.height >= 12 {
        2
    } else {
        1
    };
    let footer_h = if area.height >= 6 { 1 } else { 0 };
    let rows = Layout::vertical([
        Constraint::Length(header_h),
        Constraint::Min(3),
        Constraint::Length(footer_h),
    ])
    .split(area);

    header(f, rows[0], app);
    if area.width >= 84 {
        let cols = Layout::horizontal([Constraint::Percentage(44), Constraint::Percentage(56)]).split(rows[1]);
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
    match &mut app.mode {
        Mode::Add(s) => popup(f, area, "0xIN // INJECT CONFIGURATION PAYLOAD", "VLESS · VMESS · TROJAN · SS · HY2 · TUIC · WG · AWG · OVPN · SUB URL", s),
        Mode::Rename(s) => popup(f, area, "0xRN // MUTATE TARGET IDENTIFIER", "enter new cryptographic profile alias", s),
        Mode::Confirm => confirm_popup(f, area, app),
        Mode::Help => help(f, area),
        Mode::Qr { profile, qr, exported } => qr_popup(f, area, profile, qr, exported.as_deref()),
        Mode::Subs { list, subs } => subs_popup(f, area, list, subs),
        _ => {}
    }
}

fn header(f: &mut Frame, a: Rect, app: &App) {
    if a.height == 0 {
        return;
    }
    let left_title = Line::from(vec![
        Span::styled("⚡ VORTEX", Style::new().fg(GREEN).bold()),
        Span::styled(" // ", Style::new().fg(BORDER)),
        Span::styled("CYBER WARFARE NETWORK TUNNEL", Style::new().fg(CYAN).bold()),
        Span::styled(format!("  v{}", env!("CARGO_PKG_VERSION")), Style::new().fg(FG_DIM)),
    ]);

    let right_status = if let Some(b) = app.busy {
        let sp = SPIN[(app.busy_since.elapsed().as_millis() / 90) as usize % SPIN.len()];
        Line::from(vec![
            Span::styled(format!("[⌁ SWEEP: {b} {sp}] "), Style::new().fg(YELLOW).bold()),
            Span::styled("SCANNING ROUTE...", Style::new().fg(FG_DIM)),
        ])
    } else if let Some(s) = &app.session {
        let mut v = vec![
            Span::styled("[● LINK ENGAGED] ", Style::new().fg(GREEN).bold()),
            Span::styled(format!("{}: ", s.kind.tag()), Style::new().fg(kind_color(s.kind)).bold()),
            Span::styled(format!("{} ", trunc(&s.name, 18)), Style::new().fg(FG).bold()),
        ];
        if let Some(ms) = app.rtt {
            v.push(Span::styled(format!("{ms}ms "), Style::new().fg(ms_color(ms)).bold()));
        }
        v.push(Span::styled(
            format!("[UP: {}] ", fmt_dur(tunnel::now().saturating_sub(s.since))),
            Style::new().fg(FG_DIM),
        ));
        Line::from(v)
    } else {
        Line::from(vec![
            Span::styled("[○ STANDBY // DIRECT PROBE ACTIVE] ", Style::new().fg(FG_DIM)),
            Span::styled("[PORT: DIRECT] ", Style::new().fg(DIM)),
        ])
    };

    if a.height == 1 {
        f.render_widget(Paragraph::new(left_title), a);
        f.render_widget(Paragraph::new(right_status).alignment(Alignment::Right), a);
        return;
    }

    let (sub_line, right_sub) = if a.width >= 100 {
        (
            Line::from(vec![
                Span::styled("  SYS: ", Style::new().fg(DIM).bold()),
                Span::styled("sing-box/bpf", Style::new().fg(CYAN)),
                Span::styled("  ◈  KERNEL: ", Style::new().fg(DIM).bold()),
                Span::styled("vx0", Style::new().fg(FG)),
                Span::styled("  ◈  DNS: ", Style::new().fg(DIM).bold()),
                Span::styled("1.1.1.1:DoH", Style::new().fg(GREEN)),
                Span::styled("  ◈  ROUTE: ", Style::new().fg(DIM).bold()),
                Span::styled("STRICT", Style::new().fg(PURPLE)),
            ]),
            Line::from(vec![
                Span::styled("[SECLEVEL: ", Style::new().fg(DIM)),
                Span::styled("CLASSIFIED", Style::new().fg(GREEN).bold()),
                Span::styled(" · SHIELD: ", Style::new().fg(DIM)),
                Span::styled("ENGAGED] ", Style::new().fg(CYAN).bold()),
            ]),
        )
    } else {
        (
            Line::from(vec![
                Span::styled("  CORE: ", Style::new().fg(DIM).bold()),
                Span::styled("sing-box/bpf", Style::new().fg(CYAN)),
                Span::styled("  ◈  NET_ADMIN  ◈  MTU: 9000  ◈  DNS: DoH", Style::new().fg(FG_DIM)),
            ]),
            Line::from(vec![
                Span::styled("[LEAK_SHIELD: ", Style::new().fg(DIM)),
                Span::styled("ENGAGED] ", Style::new().fg(CYAN).bold()),
            ]),
        )
    };

    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(a);
    f.render_widget(Paragraph::new(left_title), rows[0]);
    f.render_widget(Paragraph::new(right_status).alignment(Alignment::Right), rows[0]);
    let right_len = if a.width >= 100 { 44 } else { 22 };
    let sub_cols = Layout::horizontal([Constraint::Min(20), Constraint::Length(right_len)]).split(rows[1]);
    f.render_widget(Paragraph::new(sub_line), sub_cols[0]);
    f.render_widget(Paragraph::new(right_sub).alignment(Alignment::Right), sub_cols[1]);
}

fn ping_cell(app: &App, id: &str) -> Span<'static> {
    if app.pending.contains(id) {
        return Span::styled("  ⌁ PROBING ", Style::new().fg(CYAN).bold());
    }
    match app.pings.get(id) {
        Some(Ping::Ms(ms)) => {
            let (bars, col) = if *ms < 60 {
                ("▰▰▰▰▰", GREEN)
            } else if *ms < 120 {
                ("▰▰▰▰▱", CYAN)
            } else if *ms < 250 {
                ("▰▰▰▱▱", YELLOW)
            } else if *ms < 400 {
                ("▰▰▱▱▱", Color::Rgb(0xff, 0x88, 0x00))
            } else {
                ("▰▱▱▱▱", RED)
            };
            Span::styled(format!("{bars} {ms:>3}ms "), Style::new().fg(col).bold())
        }
        Some(Ping::Timeout) => Span::styled("  ✕ TIMEOUT ", Style::new().fg(RED).bold()),
        None => Span::styled(" ▱▱▱▱▱ --ms ", Style::new().fg(DIM)),
    }
}

fn profiles(f: &mut Frame, area: Rect, app: &mut App) {
    let mut title = format!("0x01 // TARGET NODE MATRIX [ {:02} NODES ]", app.view.len());
    if !app.filter.is_empty() {
        title = format!("0x01 // SCAN: \"{}\"█ [ {} MATCHES ]", trunc(&app.filter, 12), app.view.len());
    } else if app.sort_ping {
        title = format!("0x01 // TARGET MATRIX [ {:02} NODES · ↑RTT ]", app.view.len());
    }
    if let Mode::Filter(s) = &app.mode {
        title = format!("0x01 // PATTERN SCAN: \"{}\"█", trunc(s, 16));
    }
    let blk = block(&title, app.session.is_some());
    if app.view.is_empty() {
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        let msg = if app.profiles.is_empty() {
            vec![
                Line::from(""),
                Line::from(Span::styled("[!] NO TARGET TUNNELS CONFIGURED", Style::new().fg(YELLOW).bold())),
                Line::from(""),
                Line::from(Span::styled("  A  // INJECT LINK · SUBSCRIPTION · FILE", Style::new().fg(CYAN))),
                Line::from(Span::styled("  V  // INJECT TARGET FROM CLIPBOARD", Style::new().fg(FG_DIM))),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled("[!] PATTERN SCAN: NO MATCHING TARGETS", Style::new().fg(RED).bold())),
                Line::from(Span::styled("  ESC // CLEAR SCAN FILTER", Style::new().fg(FG_DIM))),
            ]
        };
        f.render_widget(Paragraph::new(msg).alignment(Alignment::Center), inner);
        return;
    }
    let w = (area.width as usize).saturating_sub(4);
    let active = app.session.as_ref().map(|s| s.id.clone());
    let items: Vec<ListItem> = app
        .view
        .iter()
        .enumerate()
        .map(|(idx, &i)| {
            let p = &app.profiles[i];
            let on = active.as_deref() == Some(p.id.as_str());
            let num = format!("{:02} ", idx + 1);
            let tag_str = format!("[{}]", kind_badge(p.kind));
            let fixed_w = 4 + 3 + 12 + 1 + 7 + 1; // marker(4) + num(3) + ping(12) + space(1) + tag(7) + space(1) = 28
            let nw = w.saturating_sub(fixed_w).max(4);
            let name = trunc(&p.name, nw);
            let pad = nw.saturating_sub(name.chars().count());
            Line::from(vec![
                Span::styled(if on { "[●] " } else { "[○] " }, Style::new().fg(if on { GREEN } else { DIM }).bold()),
                Span::styled(num, Style::new().fg(if on { GREEN } else { FG_DIM })),
                Span::styled(name.into_owned(), Style::new().fg(if on { GREEN } else { FG }).bold()),
                Span::raw(spaces(pad + 1)),
                ping_cell(app, &p.id),
                Span::raw(" "),
                Span::styled(tag_str, Style::new().fg(kind_color(p.kind)).bold()),
            ])
            .into()
        })
        .collect();
    let list = List::new(items)
        .block(blk)
        .highlight_style(Style::new().bg(SEL_BG).fg(SEL_FG).bold())
        .highlight_symbol("► ");
    f.render_stateful_widget(list, area, &mut app.list);
}

fn circuit_diagram(local_iface: &str, node: &str, cipher: &str, exit_ip: &str, width: usize) -> Line<'static> {
    let clean_exit = if exit_ip.is_empty() { "ANALYZING..." } else { exit_ip };
    if width >= 58 {
        let fixed = 2 + local_iface.len() + 6 + cipher.len() + 7 + 7 + clean_exit.len() + 4;
        let max_node_w = width.saturating_sub(fixed).max(6);
        Line::from(vec![
            Span::styled(" [", Style::new().fg(DIM)),
            Span::styled(local_iface.to_string(), Style::new().fg(CYAN).bold()),
            Span::styled("] ══[ ", Style::new().fg(BORDER)),
            Span::styled(cipher.to_string(), Style::new().fg(PURPLE).bold()),
            Span::styled(" ]══► [", Style::new().fg(BORDER)),
            Span::styled(trunc(node, max_node_w).into_owned(), Style::new().fg(FG).bold()),
            Span::styled("] ══► [", Style::new().fg(BORDER)),
            Span::styled(clean_exit.to_string(), Style::new().fg(GREEN).bold()),
            Span::styled(" 🌐]", Style::new().fg(GREEN)),
        ])
    } else if width >= 44 {
        Line::from(vec![
            Span::styled(" [", Style::new().fg(DIM)),
            Span::styled(local_iface.to_string(), Style::new().fg(CYAN).bold()),
            Span::styled("] ──► [", Style::new().fg(BORDER)),
            Span::styled(trunc(node, 12).into_owned(), Style::new().fg(FG).bold()),
            Span::styled("] ──► [", Style::new().fg(BORDER)),
            Span::styled(clean_exit.to_string(), Style::new().fg(GREEN).bold()),
            Span::styled("]", Style::new().fg(DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" TUNNEL: ", Style::new().fg(DIM)),
            Span::styled(local_iface.to_string(), Style::new().fg(CYAN).bold()),
            Span::styled(" ──► ", Style::new().fg(BORDER)),
            Span::styled(clean_exit.to_string(), Style::new().fg(GREEN).bold()),
        ])
    }
}

fn circuit_diagram_direct(width: usize) -> Line<'static> {
    if width >= 66 {
        Line::from(vec![
            Span::styled(" [LOCAL: DIRECT] ", Style::new().fg(DIM)),
            Span::styled("──────[ UNENCRYPTED CLEAR-NET ]──────► ", Style::new().fg(RED).bold()),
            Span::styled("[PUBLIC GATEWAY]", Style::new().fg(DIM)),
        ])
    } else if width >= 50 {
        Line::from(vec![
            Span::styled(" [LOCAL: DIRECT] ", Style::new().fg(DIM)),
            Span::styled("──[ UNENCRYPTED ]──► ", Style::new().fg(RED).bold()),
            Span::styled("[GATEWAY]", Style::new().fg(DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" [DIRECT] ", Style::new().fg(DIM)),
            Span::styled("──[ CLEAR-NET ]──► ", Style::new().fg(RED).bold()),
            Span::styled("[GATEWAY]", Style::new().fg(DIM)),
        ])
    }
}

fn kv<'a>(k: &str, v: impl Into<Cow<'a, str>>, c: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!(" {:<11} ", k.to_ascii_uppercase()), Style::new().fg(FG_DIM).bold()),
        Span::styled("► ", Style::new().fg(BORDER_ACTIVE)),
        Span::styled(v.into(), Style::new().fg(c).bold()),
    ])
}

fn spark(f: &mut Frame, r: Rect, data: &[u64], c: Color) {
    let w = r.width as usize;
    let d = &data[data.len().saturating_sub(w)..];
    f.render_widget(Sparkline::default().data(d).style(Style::new().fg(c)), r);
}

fn info(f: &mut Frame, area: Rect, app: &App) {
    if app.show_log {
        let blk = block("0x04 // REAL-TIME KERNEL AUDIT & CORE LOGS", true);
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        let inner = inner.inner(Margin::new(1, 1));
        let lines: Vec<Line> = tunnel::tail_log(inner.height as usize)
            .into_iter()
            .map(|l| {
                let lower = l.to_lowercase();
                let (prefix, c) = if lower.contains("error") || lower.contains("fatal") || lower.contains("panic") {
                    ("[✕ ALERT] ", RED)
                } else if lower.contains("warn") {
                    ("[! WARN ] ", YELLOW)
                } else if lower.contains("connected") || lower.contains("ready") || lower.contains("success") || lower.contains("started") {
                    ("[✔ OK   ] ", GREEN)
                } else if lower.contains("dns") || lower.contains("route") || lower.contains("tun") || lower.contains("inbound") {
                    ("[◈ NET  ] ", CYAN)
                } else {
                    ("[· CORE ] ", FG_DIM)
                };
                Line::from(vec![
                    Span::styled(prefix, Style::new().fg(c).bold()),
                    Span::styled(l, Style::new().fg(if c == RED { RED } else { FG })),
                ])
            })
            .collect();
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        return;
    }

    let sel = app.cur();
    let shown = match (&app.session, sel) {
        (Some(s), _) => Some((s.name.clone(), s.kind, s.server.clone())),
        (None, Some(p)) => Some((p.name.clone(), p.kind, p.server.clone())),
        _ => None,
    };
    let Some((name, kind, server)) = shown else {
        f.render_widget(block("0x02 // ROUTE DISENGAGED // NO SELECTION", false), area);
        return;
    };

    let parts = Layout::vertical([Constraint::Length(12), Constraint::Min(4)]).split(area);
    let is_connected = app.session.is_some();

    // ── connection card
    let blk = block("0x02 // TELEMETRY & TACTICAL ROUTE INSPECTOR", is_connected);
    let inner = blk.inner(parts[0]).inner(Margin::new(1, 0));
    f.render_widget(blk, parts[0]);
    let nw = (inner.width as usize).saturating_sub(16);
    let mut lines = vec![];
    match &app.session {
        Some(s) => {
            let cipher_tag = if inner.width >= 72 { "CHACHA20-POLY1305" } else { "CHACHA20" };
            lines.push(circuit_diagram(&s.iface, &s.server, cipher_tag, &app.ip, inner.width as usize));
            lines.push(Line::from(""));
            lines.push(kv("status", "● ENGAGED // ENCRYPTED TUNNEL ACTIVE", GREEN));
            lines.push(kv("target", trunc(&name, nw), FG));
            lines.push(kv("protocol", format!("{} [STRICT-ROUTE / TUN]", s.kind.tag()), kind_color(s.kind)));
            lines.push(kv("endpoint", trunc(&server, nw), FG));
            lines.push(kv("exit ip", if app.ip.is_empty() { "ANALYZING IP..." } else { &app.ip }, CYAN));
            lines.push(kv("uptime", format!("{} [SESSION: 0x{:04X}]", fmt_dur(tunnel::now().saturating_sub(s.since)), s.pid.unwrap_or(0) & 0xFFFF), FG_DIM));
            lines.push(match app.rtt {
                Some(ms) => kv("latency", format!("{ms} ms [REALTIME ICMP ECHO]"), ms_color(ms)),
                None => kv("latency", "PROBING ICMP...", FG_DIM),
            });
            lines.push(kv("shield", "DNS-OVER-HTTPS [1.1.1.1] · IPV6 ISOLATED", GREEN));
        }
        None => {
            lines.push(circuit_diagram_direct(inner.width as usize));
            lines.push(Line::from(vec![
                Span::styled("  [!] ALERT: ", Style::new().fg(RED).bold()),
                Span::styled("INTERNET TRAFFIC UNPROTECTED · LOCAL IP VISIBLE", Style::new().fg(FG_DIM)),
            ]));
            lines.push(Line::from(""));
            lines.push(kv("status", "○ STANDBY // ROUTE DISENGAGED", FG_DIM));
            lines.push(kv("target", trunc(&name, nw), FG));
            lines.push(kv("protocol", kind.tag(), kind_color(kind)));
            lines.push(kv("endpoint", trunc(&server, nw), FG));
            let id = sel.map(|p| p.id.as_str()).unwrap_or("");
            lines.push(match app.pings.get(id) {
                Some(Ping::Ms(ms)) => kv("probe rtt", format!("{ms} ms [TELEMETRY OPTIMAL]"), ms_color(*ms)),
                Some(Ping::Timeout) => kv("probe rtt", "UNREACHABLE / TIMEOUT [✕]", RED),
                None => kv("probe rtt", "NO TELEMETRY [PRESS T TO PROBE]", FG_DIM),
            });
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  [⏎] ENGAGE NODE  ", Style::new().fg(CYAN).bold()),
                Span::styled(" [T] PROBE LATENCY  ", Style::new().fg(YELLOW).bold()),
                Span::styled(" [U] AUTH CREDENTIALS", Style::new().fg(FG_DIM)),
            ]));
        }
    }
    f.render_widget(Paragraph::new(lines), inner);

    // ── traffic (connected) / details (idle)
    if is_connected {
        let blk = block("0x03 // PACKET FLOW & SPECTRUM ANALYZER", true);
        let inner = blk.inner(parts[1]).inner(Margin::new(1, 0));
        f.render_widget(blk, parts[1]);
        let rows = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Min(0),
        ])
        .split(inner);
        let dn = app.down.last().copied().unwrap_or(0);
        let upn = app.up.last().copied().unwrap_or(0);
        let tot = app.last.map(|(r, t)| (r.saturating_sub(app.base.0), t.saturating_sub(app.base.1))).unwrap_or((0, 0));
        let line = if inner.width >= 62 {
            Line::from(vec![
                Span::styled("RX SPEED ► ", Style::new().fg(CYAN).bold()),
                Span::styled(format!("{}/s", fmt_bytes(dn)), Style::new().fg(FG).bold()),
                Span::styled(format!(" [PEAK: {}/s]", fmt_bytes(app.down_peak)), Style::new().fg(FG_DIM)),
                Span::raw("   "),
                Span::styled("TX SPEED ▲ ", Style::new().fg(PURPLE).bold()),
                Span::styled(format!("{}/s", fmt_bytes(upn)), Style::new().fg(FG).bold()),
                Span::styled(format!(" [PEAK: {}/s]", fmt_bytes(app.up_peak)), Style::new().fg(FG_DIM)),
            ])
        } else {
            Line::from(vec![
                Span::styled("RX ► ", Style::new().fg(CYAN).bold()),
                Span::styled(format!("{}/s ", fmt_bytes(dn)), Style::new().fg(FG).bold()),
                Span::styled("  TX ▲ ", Style::new().fg(PURPLE).bold()),
                Span::styled(format!("{}/s", fmt_bytes(upn)), Style::new().fg(FG).bold()),
            ])
        };
        let sub = if inner.width >= 62 {
            Line::from(vec![
                Span::styled("CUMULATIVE: ", Style::new().fg(DIM).bold()),
                Span::styled(format!("RX {} · TX {}", fmt_bytes(tot.0), fmt_bytes(tot.1)), Style::new().fg(FG_DIM)),
                Span::styled("  │  MTU: 9000  │  BBR: ENGAGED", Style::new().fg(GREEN)),
            ])
        } else {
            Line::from(vec![
                Span::styled("TOTAL: ", Style::new().fg(DIM)),
                Span::styled(format!("RX {} · TX {}", fmt_bytes(tot.0), fmt_bytes(tot.1)), Style::new().fg(FG_DIM)),
            ])
        };
        f.render_widget(Paragraph::new(line), rows[0]);
        f.render_widget(Paragraph::new(sub), rows[1]);
        spark(f, rows[2], &app.down, CYAN);
        spark(f, rows[3], &app.up, PURPLE);
        let (lo, hi) = (app.rtt_hist.iter().min(), app.rtt_hist.iter().max());
        let cur_rtt = app.rtt.unwrap_or(0);
        let rtt_txt = match (lo, hi) {
            (Some(l), Some(h)) => format!("⌁ RTT JITTER SPECTRUM   MIN {l}ms · CUR {cur_rtt}ms · MAX {h}ms   [ICMP ECHO]"),
            _ => "⌁ RTT JITTER SPECTRUM".to_string(),
        };
        f.render_widget(Paragraph::new(Span::styled(rtt_txt, Style::new().fg(FG_DIM).bold())), rows[4]);
        spark(f, rows[5], &app.rtt_hist, YELLOW);
    } else {
        let blk = block("0x03 // TARGET ENCRYPTED PARAMETERS & RECON VECTOR", false);
        let inner = blk.inner(parts[1]).inner(Margin::new(1, 0));
        f.render_widget(blk, parts[1]);
        let mut lines: Vec<Line> = sel
            .map(store::details)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(i, (k, v))| {
                let prefix = format!("0x{:02X} {:<11} ", i + 1, k.to_ascii_uppercase());
                Line::from(vec![
                    Span::styled(prefix, Style::new().fg(FG_DIM).bold()),
                    Span::styled("► ", Style::new().fg(BORDER_ACTIVE)),
                    Span::styled(trunc(&v, nw).into_owned(), Style::new().fg(FG).bold()),
                ])
            })
            .collect();

        if inner.height >= 9 && inner.width >= 60 {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(" ┌─[ TARGET VECTOR INTELLIGENCE ]──────────────────────────┐", Style::new().fg(BORDER))));
            lines.push(Line::from(vec![
                Span::styled(" │ CORE: ", Style::new().fg(BORDER)),
                Span::styled("sing-box/bpf       ", Style::new().fg(CYAN)),
                Span::styled(" ROUTING: ", Style::new().fg(BORDER)),
                Span::styled("STRICT-ROUTE (vx0) ", Style::new().fg(FG)),
                Span::styled("│", Style::new().fg(BORDER)),
            ]));
            lines.push(Line::from(vec![
                Span::styled(" │ DNS : ", Style::new().fg(BORDER)),
                Span::styled("1.1.1.1 (DoH)      ", Style::new().fg(GREEN)),
                Span::styled(" SHIELD : ", Style::new().fg(BORDER)),
                Span::styled("KILL-SWITCH ARMED  ", Style::new().fg(PURPLE)),
                Span::styled("│", Style::new().fg(BORDER)),
            ]));
            lines.push(Line::from(Span::styled(" └────────────────────────────────────────────────────────┘", Style::new().fg(BORDER))));
        }
        f.render_widget(Paragraph::new(lines), inner);
    }
}

fn footer(f: &mut Frame, a: Rect, app: &App) {
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
        f.render_widget(Paragraph::new(Span::styled(text, Style::new().fg(c).bold())), a);
        return;
    }
    let mut sp = vec![
        Span::styled(" root@vortex", Style::new().fg(GREEN).bold()),
        Span::styled("[SYS]# ", Style::new().fg(CYAN).bold()),
    ];
    let keys = [
        ("RET", "ENGAGE"),
        ("SPC", "SEVER"),
        ("A", "INJECT"),
        ("C", "QR/CONF"),
        ("B", "SUBS"),
        ("S", "SYNC"),
        ("T", "PROBE"),
        ("U", "AUTH"),
        ("/", "SCAN"),
        ("O", "SORT"),
        ("L", "LOG"),
        ("?", "HELP"),
        ("Q", "QUIT"),
    ];
    for (k, d) in keys {
        sp.push(Span::styled(format!("[{k}]"), Style::new().fg(CYAN).bold()));
        sp.push(Span::styled(format!(" {d} "), Style::new().fg(FG_DIM)));
    }
    f.render_widget(Paragraph::new(Line::from(sp)), a);
}

fn popup(f: &mut Frame, area: Rect, title: &str, hint: &str, input: &str) {
    let w = area.width.min(78);
    let h = 5.min(area.height);
    let r = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block(title, true);
    let inner = blk.inner(r);
    f.render_widget(blk, r);
    let max = (inner.width as usize).saturating_sub(26);
    let n = input.chars().count();
    let shown: String = input.chars().skip(n.saturating_sub(max)).collect();
    let lines = vec![
        Line::from(vec![
            Span::styled(" ⌁ VECTOR PROTOCOL: ", Style::new().fg(CYAN).bold()),
            Span::styled(hint, Style::new().fg(FG_DIM)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" root@vortex:payload# ", Style::new().fg(GREEN).bold()),
            Span::styled(shown, Style::new().fg(FG).bold()),
            Span::styled("█", Style::new().fg(CYAN)),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn confirm_popup(f: &mut Frame, area: Rect, app: &App) {
    let Some(p) = app.cur() else { return };
    let w = 64.min(area.width);
    let h = 7.min(area.height);
    let r = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = Block::bordered()
        .border_type(BorderType::Plain)
        .border_style(Style::new().fg(RED))
        .title(Line::from(vec![
            Span::styled(" ◈ [ ", Style::new().fg(RED)),
            Span::styled("0xDEL // TARGET PURGE CONFIRMATION", Style::new().fg(RED).bold()),
            Span::styled(" ] ", Style::new().fg(RED)),
        ]));
    let inner = blk.inner(r).inner(Margin::new(2, 1));
    f.render_widget(blk, r);
    let lines = vec![
        Line::from(vec![
            Span::styled("[!] CRITICAL: ", Style::new().fg(RED).bold()),
            Span::styled("PERMANENT NODE VECTOR PURGE", Style::new().fg(FG).bold()),
        ]),
        Line::from(vec![
            Span::styled("TARGET: ", Style::new().fg(FG_DIM)),
            Span::styled(trunc(&p.name, (inner.width as usize).saturating_sub(10)), Style::new().fg(YELLOW).bold()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("PRESS [", Style::new().fg(FG_DIM)),
            Span::styled("Y", Style::new().fg(GREEN).bold()),
            Span::styled("] TO CONFIRM PURGE  ·  [", Style::new().fg(FG_DIM)),
            Span::styled("ESC", Style::new().fg(RED).bold()),
            Span::styled("] TO ABORT", Style::new().fg(FG_DIM)),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn time_ago(ts: Option<u64>) -> String {
    let Some(ts) = ts else { return "never".to_string() };
    let diff = crate::tunnel::now().saturating_sub(ts);
    if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

fn qr_popup(f: &mut Frame, area: Rect, p: &Profile, qr: &Result<String, String>, exported: Option<&str>) {
    let w = (area.width.saturating_sub(2)).min(94);
    let h = (area.height.saturating_sub(2)).min(32);
    let r = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block("0xQR // CONFIGURATION & QR EXPORT MATRIX", true);
    let inner = blk.inner(r);
    f.render_widget(blk, r);

    let qr_req_w = 54;
    let chunks = if inner.width >= 75 {
        Layout::horizontal([
            Constraint::Length(qr_req_w.min(inner.width * 55 / 100)),
            Constraint::Min(20),
        ])
        .split(inner)
    } else {
        Layout::vertical([
            Constraint::Percentage(55),
            Constraint::Percentage(45),
        ])
        .split(inner)
    };

    let qr_blk = Block::bordered()
        .border_type(BorderType::Plain)
        .border_style(Style::new().fg(BORDER))
        .title(Line::from(vec![
            Span::styled(" ◈ [ ", Style::new().fg(BORDER)),
            Span::styled("TERMINAL QR CODE", Style::new().fg(CYAN).bold()),
            Span::styled(" ] ", Style::new().fg(BORDER)),
        ]));
    let qr_inner = qr_blk.inner(chunks[0]);
    f.render_widget(qr_blk, chunks[0]);

    match qr {
        Ok(code) => {
            let lines: Vec<Line> = code
                .lines()
                .map(|l| Line::from(Span::styled(l, Style::new().fg(FG).bold())))
                .collect();
            f.render_widget(Paragraph::new(lines), qr_inner);
        }
        Err(e) => {
            let warn = vec![
                Line::from(""),
                Line::from(Span::styled("[!] QR CODE PAYLOAD LIMIT EXCEEDED", Style::new().fg(YELLOW).bold())),
                Line::from(""),
                Line::from(Span::styled(e.clone(), Style::new().fg(FG_DIM))),
                Line::from(""),
                Line::from(Span::styled("Use [C] to copy raw config to clipboard,", Style::new().fg(FG))),
                Line::from(Span::styled("or [S] to export directly to disk.", Style::new().fg(FG))),
            ];
            f.render_widget(Paragraph::new(warn), qr_inner);
        }
    }

    let det_blk = Block::bordered()
        .border_type(BorderType::Plain)
        .border_style(Style::new().fg(BORDER))
        .title(Line::from(vec![
            Span::styled(" ◈ [ ", Style::new().fg(BORDER)),
            Span::styled("NODE TELEMETRY & CREDENTIALS", Style::new().fg(CYAN).bold()),
            Span::styled(" ] ", Style::new().fg(BORDER)),
        ]));
    let det_inner = det_blk.inner(chunks[1]);
    f.render_widget(det_blk, chunks[1]);

    let mut lines = vec![
        Line::from(vec![
            Span::styled(" IDENTIFIER : ", Style::new().fg(CYAN).bold()),
            Span::styled(trunc(&p.name, (det_inner.width as usize).saturating_sub(15)), Style::new().fg(FG).bold()),
        ]),
        Line::from(vec![
            Span::styled(" PROTOCOL   : ", Style::new().fg(CYAN).bold()),
            Span::styled(format!("{} ", p.kind.tag()), Style::new().fg(kind_color(p.kind)).bold()),
            Span::styled(format!("({})", p.id), Style::new().fg(FG_DIM)),
        ]),
        Line::from(vec![
            Span::styled(" ENDPOINT   : ", Style::new().fg(CYAN).bold()),
            Span::styled(&p.server, Style::new().fg(FG).bold()),
        ]),
    ];

    for (k, v) in store::details(p) {
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<11}: ", k.to_uppercase()), Style::new().fg(FG_DIM)),
            Span::styled(v, Style::new().fg(FG)),
        ]));
    }

    lines.push(Line::from(""));
    let exp_status = if let Some(path) = exported {
        Line::from(vec![
            Span::styled(" EXPORT FILE: ", Style::new().fg(GREEN).bold()),
            Span::styled(trunc(path, (det_inner.width as usize).saturating_sub(15)), Style::new().fg(GREEN)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" EXPORT FILE: ", Style::new().fg(BORDER)),
            Span::styled("NOT SAVED TO DISK", Style::new().fg(FG_DIM)),
        ])
    };
    lines.push(exp_status);

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(" ── ACTION CONTROLS ─────────────────", Style::new().fg(BORDER))));
    lines.push(Line::from(vec![
        Span::styled(" [C] ", Style::new().fg(CYAN).bold()),
        Span::styled("COPY FULL PAYLOAD TO CLIPBOARD", Style::new().fg(FG)),
    ]));
    lines.push(Line::from(vec![
        Span::styled(" [S] ", Style::new().fg(GREEN).bold()),
        Span::styled("EXPORT CONFIG FILE (~/vortex-*.conf)", Style::new().fg(FG)),
    ]));
    lines.push(Line::from(vec![
        Span::styled(" [ESC] ", Style::new().fg(RED).bold()),
        Span::styled("DISMISS MATRIX", Style::new().fg(FG_DIM)),
    ]));

    f.render_widget(Paragraph::new(lines), det_inner);
}

fn subs_popup(f: &mut Frame, area: Rect, list: &mut ListState, subs: &[store::Subscription]) {
    let w = (area.width.saturating_sub(4)).min(88);
    let h = (area.height.saturating_sub(4)).min(20);
    let r = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block("0xSUB // SUBSCRIPTION REGISTRY & SYNC MANAGER", true);
    let inner = blk.inner(r);
    f.render_widget(blk, r);

    let rows = Layout::vertical([
        Constraint::Length(2), // Table header
        Constraint::Min(3),    // List of subs
        Constraint::Length(2), // Bottom hints
    ])
    .split(inner);

    let header_line = Line::from(vec![
        Span::styled("  #  ", Style::new().fg(CYAN).bold()),
        Span::styled("ALIAS / NAME            ", Style::new().fg(CYAN).bold()),
        Span::styled("NODES   ", Style::new().fg(CYAN).bold()),
        Span::styled("LAST SYNC     ", Style::new().fg(CYAN).bold()),
        Span::styled("ENDPOINT URL", Style::new().fg(CYAN).bold()),
    ]);
    let sep = Line::from(Span::styled(" ─────────────────────────────────────────────────────────────────────────────", Style::new().fg(BORDER)));
    f.render_widget(Paragraph::new(vec![header_line, sep]), rows[0]);

    if subs.is_empty() {
        let empty_msg = vec![
            Line::from(""),
            Line::from(Span::styled("  [!] NO REMOTE SUBSCRIPTIONS REGISTERED", Style::new().fg(YELLOW).bold())),
            Line::from(Span::styled("  PRESS [A] TO INJECT A SUBSCRIPTION URL (e.g. https://...)", Style::new().fg(FG_DIM))),
        ];
        f.render_widget(Paragraph::new(empty_msg), rows[1]);
    } else {
        let items: Vec<ListItem> = subs
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let up = time_ago(s.updated);
                let line = Line::from(vec![
                    Span::styled(format!(" {:>2}  ", i + 1), Style::new().fg(BORDER)),
                    Span::styled(format!("{:<24} ", trunc(&s.name, 23)), Style::new().fg(FG).bold()),
                    Span::styled(format!("{:>4} nodes  ", s.count), Style::new().fg(GREEN)),
                    Span::styled(format!("{:<13} ", up), Style::new().fg(FG_DIM)),
                    Span::styled(trunc(&s.url, 26), Style::new().fg(BLUE)),
                ]);
                ListItem::new(line)
            })
            .collect();

        let list_widget = List::new(items)
            .highlight_style(Style::new().bg(SEL_BG).fg(SEL_FG).bold())
            .highlight_symbol("▶ ");
        f.render_stateful_widget(list_widget, rows[1], list);
    }

    let controls = Line::from(vec![
        Span::styled(" [RET/U] ", Style::new().fg(GREEN).bold()),
        Span::styled("SYNC SELECTED  ", Style::new().fg(FG_DIM)),
        Span::styled("[S] ", Style::new().fg(CYAN).bold()),
        Span::styled("SYNC ALL  ", Style::new().fg(FG_DIM)),
        Span::styled("[A] ", Style::new().fg(YELLOW).bold()),
        Span::styled("ADD SUB  ", Style::new().fg(FG_DIM)),
        Span::styled("[D] ", Style::new().fg(RED).bold()),
        Span::styled("PURGE  ", Style::new().fg(FG_DIM)),
        Span::styled("[ESC] ", Style::new().fg(FG_DIM).bold()),
        Span::styled("CLOSE", Style::new().fg(FG_DIM)),
    ]);
    f.render_widget(Paragraph::new(vec![Line::from(""), controls]), rows[2]);
}

fn help(f: &mut Frame, area: Rect) {
    let rows: [(&str, &str, &str); 20] = [
        ("TUNNEL CONTROL", "RET / ENTER", "ENGAGE SELECTED TARGET NODE"),
        ("TUNNEL CONTROL", "SPC / S", "SEVER / ABORT ACTIVE TUNNEL"),
        ("TUNNEL CONTROL", "J K ↑ ↓", "NAVIGATE TARGET NODE MATRIX"),
        ("TUNNEL CONTROL", "G / SHIFT+G", "JUMP TO FIRST / LAST NODE"),
        ("RECON & PROBE", "T", "EXECUTE LATENCY PROBE (ALL NODES)"),
        ("RECON & PROBE", "SHIFT+T", "EXECUTE LATENCY PROBE (SELECTED)"),
        ("RECON & PROBE", "O", "CYCLE SORT ORDER (RTT SPEED ⇄ ID)"),
        ("RECON & PROBE", "/", "PATTERN SCAN & GREP FILTER"),
        ("RECON & PROBE", "I", "PROBE LIVE PUBLIC EXIT IP"),
        ("PAYLOAD & AUTH", "C", "RENDER QR CODE & CONFIGURATION INSPECTOR"),
        ("PAYLOAD & AUTH", "A", "INJECT LINK / SUBSCRIPTION / FILE / QR IMAGE"),
        ("PAYLOAD & AUTH", "V", "INJECT VECTOR / QR SCREENSHOT FROM CLIPBOARD"),
        ("PAYLOAD & AUTH", "U", "CONFIGURE OPENVPN CREDENTIAL VAULT"),
        ("PAYLOAD & AUTH", "R", "MUTATE TARGET IDENTIFIER (RENAME)"),
        ("PAYLOAD & AUTH", "D", "PURGE TARGET VECTOR FROM KEYSTORE"),
        ("SUBSCRIPTION", "B", "OPEN SUBSCRIPTION REGISTRY MANAGER"),
        ("SUBSCRIPTION", "SHIFT+S", "EXECUTE RECURSIVE SYNC ON ALL SUBS"),
        ("SYSTEM OPS", "L", "TOGGLE KERNEL AUDIT & LIVE LOGS"),
        ("SYSTEM OPS", "ESC", "DISMISS / CLEAR FILTER / ABORT"),
        ("SYSTEM OPS", "Q / SHIFT+Q", "DETACH CONSOLE / TERMINATE ALL"),
    ];
    let h = (rows.len() as u16 + 5).min(area.height);
    let w = 68.min(area.width);
    let r = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block("0x?? // BLACK-HAT COMMAND CONSOLE DIRECTORY", true);
    let inner = blk.inner(r).inner(Margin::new(1, 1));
    f.render_widget(blk, r);
    let mut lines = vec![];
    let mut last_cat = "";
    for (cat, k, d) in rows {
        if cat != last_cat && inner.height >= 20 {
            lines.push(Line::from(Span::styled(format!(" // {cat}"), Style::new().fg(CYAN).bold())));
            last_cat = cat;
        }
        lines.push(Line::from(vec![
            Span::styled(format!(" [{k:<11}] "), Style::new().fg(if k.contains("RET") || k.contains("SPC") { GREEN } else { CYAN }).bold()),
            Span::styled("► ", Style::new().fg(BORDER_ACTIVE)),
            Span::styled(d, Style::new().fg(FG)),
        ]));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn prof(id: &str, name: &str, kind: Kind, data: &str) -> Profile {
        Profile { id: id.into(), name: name.into(), kind, server: "203.0.113.7:443".into(), data: data.into(), auth: None, sub_id: None }
    }

    fn render(w: u16, h: u16, app: &mut App) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        let b = t.backend().buffer().clone();
        (0..h).map(|y| (0..w).map(|x| b[(x, y)].symbol().to_string()).collect::<String>()).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn layouts_do_not_panic_and_show_latency() {
        let mut app = App::new();
        app.profiles = vec![
            prof("a", "Frankfurt Reality", Kind::Vless, "vless://u@203.0.113.7:443?security=reality&sni=example.com&pbk=k&type=grpc&serviceName=x#Frankfurt"),
            prof("b", "Home WG", Kind::Wg, "[Peer]\nEndpoint = 203.0.113.7:51820\n"),
            prof("c", "Dead one", Kind::Hy2, "hy2://pw@203.0.113.7:443#Dead"),
        ];
        app.pings.insert("a".into(), Ping::Ms(42));
        app.pings.insert("b".into(), Ping::Ms(280));
        app.pings.insert("c".into(), Ping::Timeout);
        app.rebuild();
        for (w, h) in [(120, 32), (90, 24), (70, 20), (30, 8), (12, 4)] {
            let out = render(w, h, &mut app);
            if w == 120 {
                println!("{out}");
            }
        }
        app.sort_ping = true;
        app.rebuild();
        assert_eq!(app.cur().map(|p| p.id.as_str()), Some("a"));
        app.filter = "wg".into();
        app.rebuild();
        assert_eq!(app.view.len(), 1);
        app.mode = Mode::Help;
        render(80, 24, &mut app);
        app.mode = Mode::Rename("x".into());
        render(80, 24, &mut app);
    }

    #[test]
    fn edit_keys() {
        let k = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
        let mut s = String::from("ab cd");
        assert!(edit(&mut s, &k('e')));
        assert_eq!(s, "ab cde");
        assert!(edit(&mut s, &KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL)));
        assert_eq!(s, "ab ");
        assert!(edit(&mut s, &KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)));
        assert_eq!(s, "");
    }

    #[test]
    fn connected_layout_renders_properly() {
        let mut app = App::new();
        let p = prof("a", "Frankfurt Reality", Kind::Vless, "vless://u@203.0.113.7:443?security=reality&sni=example.com&pbk=k&type=grpc&serviceName=x#Frankfurt");
        app.profiles = vec![p.clone()];
        app.view = vec![0];
        app.session = Some(Session {
            id: "a".into(),
            name: "Frankfurt Reality".into(),
            kind: Kind::Vless,
            server: "203.0.113.7:443".into(),
            iface: "vx0".into(),
            pid: Some(1337),
            since: tunnel::now().saturating_sub(120),
            conf: "".into(),
        });
        app.down = vec![1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144];
        app.up = vec![512, 1024, 2048, 4096, 8192, 16384, 32768];
        app.down_peak = 262144;
        app.up_peak = 32768;
        app.rtt_hist = vec![42, 41, 43, 42, 45, 42, 40, 42];
        app.rtt = Some(42);
        app.ip = "185.220.101.5".into();
        let out = render(120, 32, &mut app);
        println!("{out}");
        assert!(out.contains("LINK ENGAGED"));
        assert!(out.contains("CHACHA20"));
        assert!(out.contains("PACKET FLOW & SPECTRUM ANALYZER"));
    }

    #[test]
    fn test_qr_generation() {
        use qrcode::QrCode;
        use qrcode::render::unicode;
        let link = "vless://b6a03649-61f4-41aa-a51b-402c3cc6c547@203.0.113.7:443?security=reality&sni=example.com&pbk=1234567890abcdef1234567890abcdef1234567890a&type=grpc&serviceName=grpc-test#Frankfurt";
        let code = QrCode::new(link).unwrap();
        let qr_str = code.render::<unicode::Dense1x2>().quiet_zone(false).build();
        let lines: Vec<&str> = qr_str.lines().collect();
        println!("QR (no quiet zone) lines: {}, width: {}", lines.len(), lines.first().map(|l| l.chars().count()).unwrap_or(0));
        println!("\n{qr_str}\n");
    }

    #[test]
    fn test_qr_modal_render() {
        let mut app = App::new();
        let p = prof("test-qr", "Frankfurt QR", Kind::Vless, "vless://u@example.com:443?security=reality#Frankfurt");
        let qr = store::generate_qr(&p.data).map_err(|e| format!("{e}"));
        app.mode = Mode::Qr { profile: p, qr, exported: Some("~/vortex-test-qr.conf".into()) };
        let out = render(100, 30, &mut app);
        assert!(out.contains("0xQR // CONFIGURATION & QR EXPORT MATRIX"));
        assert!(out.contains("NODE TELEMETRY & CREDENTIALS"));
        assert!(out.contains("Frankfurt QR"));
        assert!(out.contains("EXPORT FILE"));
    }

    #[test]
    fn test_subs_modal_render() {
        let mut app = App::new();
        let mut list = ListState::default();
        list.select(Some(0));
        let subs = vec![
            store::Subscription {
                id: "vip-node".into(),
                name: "VIP Dedicated Nodes".into(),
                url: "https://example.com/sub/token".into(),
                count: 12,
                updated: Some(1720000000),
            },
        ];
        app.mode = Mode::Subs { list, subs };
        let out = render(100, 30, &mut app);
        assert!(out.contains("0xSUB // SUBSCRIPTION REGISTRY & SYNC MANAGER"));
        assert!(out.contains("VIP Dedicated Nodes"));
        assert!(out.contains("12 nodes"));
    }

    #[test]
    fn test_ui_hotkeys_navigation() {
        let mut app = App::new();
        let p = prof("test-hk", "HotKey Node", Kind::Vless, "vless://u@example.com:443#HotKey");
        app.profiles = vec![p];
        app.rebuild();
        assert_eq!(app.view.len(), 1);

        // Press 'c' to open QR modal
        app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
        assert!(matches!(app.mode, Mode::Qr { .. }));

        // Press Esc to dismiss QR modal
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(app.mode, Mode::Normal));

        // Press 'b' to open Subs modal
        app.key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        assert!(matches!(app.mode, Mode::Subs { .. }));

        // Press Esc to dismiss Subs modal
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(app.mode, Mode::Normal));
    }
}
