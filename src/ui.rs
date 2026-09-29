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

// Cyber / BlackHat Telemetry Palette
const FG: Color = Color::Rgb(0xd6, 0xe4, 0xf0);
const DIM: Color = Color::Rgb(0x4a, 0x5b, 0x6e);
const CYAN: Color = Color::Rgb(0x00, 0xf0, 0xff);
const PURPLE: Color = Color::Rgb(0xb0, 0x5c, 0xff);
const BLUE: Color = Color::Rgb(0x2d, 0x9c, 0xdb);
const GREEN: Color = Color::Rgb(0x00, 0xff, 0x77);
const YELLOW: Color = Color::Rgb(0xff, 0xb8, 0x00);
const RED: Color = Color::Rgb(0xff, 0x33, 0x55);
const BORDER: Color = Color::Rgb(0x18, 0x38, 0x48);
const SEL_BG: Color = Color::Rgb(0x0c, 0x24, 0x33);
const SPIN: [char; 8] = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];
const HIST: usize = 240;

enum Msg {
    Connected(Result<Session, String>),
    Disconnected(Result<(), String>),
    Imported(Result<usize, String>),
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

    fn paste_clip(&mut self) {
        let out = Command::new("wl-paste").arg("-n").output().ok().filter(|o| o.status.success());
        match out.map(|o| String::from_utf8_lossy(&o.stdout).to_string()) {
            Some(s) if !s.trim().is_empty() => self.import(s),
            _ => self.toast("clipboard empty — or paste with ctrl+shift+v", false),
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
                    self.rtt_hist.clear();
                    self.rtt = None;
                    self.toast(format!("connected · {}", s.name), true);
                    self.session = Some(s);
                    self.spawn_ip();
                }
                Msg::Connected(Err(e)) => {
                    self.busy = None;
                    self.session = tunnel::load_session();
                    self.toast(e, false);
                }
                Msg::Disconnected(r) => {
                    self.busy = None;
                    self.session = None;
                    self.ip.clear();
                    self.rtt = None;
                    match r {
                        Ok(()) => self.toast("disconnected", true),
                        Err(e) => self.toast(e, false),
                    }
                }
                Msg::Imported(Ok(n)) => {
                    self.busy = None;
                    self.reload();
                    if n == 0 {
                        self.toast("nothing new — already imported", false);
                    } else {
                        self.toast(format!("added {n} profile(s)"), true);
                        self.test(false);
                    }
                }
                Msg::Imported(Err(e)) => {
                    self.busy = None;
                    self.toast(e, false);
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
                self.toast("tunnel dropped", false);
            }
            Some(s) => {
                if let Some((rb, tb)) = tunnel::bytes(&s.iface) {
                    if let Some((lr, lt)) = self.last {
                        push(&mut self.down, rb.saturating_sub(lr));
                        push(&mut self.up, tb.saturating_sub(lt));
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
                if k.code == Char('y') {
                    self.delete();
                }
                return false;
            }
            Mode::Help => return false,
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
            Char('a') => self.mode = Mode::Add(String::new()),
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
        Kind::Vless | Kind::Vmess | Kind::Ss => CYAN,
        Kind::Trojan => BLUE,
        Kind::Hy2 | Kind::Tuic => PURPLE,
        Kind::Wg => GREEN,
        Kind::Awg => CYAN,
        Kind::Ovpn => YELLOW,
    }
}

fn ms_color(ms: u32) -> Color {
    if ms < 100 {
        GREEN
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

fn block(title: &str) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(BORDER))
        .title(Span::styled(format!(" ◈ [ {title} ] "), Style::new().fg(CYAN).bold()))
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let rows = Layout::vertical([Constraint::Length(2), Constraint::Min(3), Constraint::Length(1)]).split(area);
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
    footer(f, rows[2], app);
    match &app.mode {
        Mode::Add(s) => popup(f, area, "0xIN // INJECT CONFIG", "share link · subscription URL · .conf / .ovpn path", s),
        Mode::Rename(s) => popup(f, area, "0xRN // RENAME TARGET", "new profile identifier", s),
        Mode::Help => help(f, area),
        _ => {}
    }
}

fn header(f: &mut Frame, a: Rect, app: &App) {
    let title_line = Line::from(vec![
        Span::styled("⚡ VORTEX", Style::new().fg(GREEN).bold()),
        Span::styled(" // ", Style::new().fg(BORDER)),
        Span::styled("CYBER ROUTER", Style::new().fg(CYAN).bold()),
        Span::styled(format!("  v{}", env!("CARGO_PKG_VERSION")), Style::new().fg(DIM)),
        Span::styled("  [KERNEL: NET_ADMIN · MTU: 9000]", Style::new().fg(DIM)),
    ]);
    f.render_widget(Paragraph::new(title_line), a);

    let st = if let Some(b) = app.busy {
        let sp = SPIN[(app.busy_since.elapsed().as_millis() / 90) as usize % SPIN.len()];
        Line::from(Span::styled(format!("[⚡ SCAN: {b} {sp}] "), Style::new().fg(YELLOW).bold()))
    } else if let Some(s) = &app.session {
        let mut v = vec![
            Span::styled("[● LINK ENGAGED] ", Style::new().fg(GREEN).bold()),
            Span::styled(format!("TARGET: {} ", s.name), Style::new().fg(FG).bold()),
            Span::styled(format!("[{}] ", s.kind.tag()), Style::new().fg(kind_color(s.kind)).bold()),
        ];
        if let Some(ms) = app.rtt {
            v.push(Span::styled(format!("{ms}ms "), Style::new().fg(ms_color(ms)).bold()));
        }
        v.push(Span::styled(format!("UPTIME: {} ", fmt_dur(tunnel::now().saturating_sub(s.since))), Style::new().fg(DIM)));
        Line::from(v)
    } else {
        Line::from(Span::styled("[○ DISENGAGED // DIRECT PROBE ACTIVE] ", Style::new().fg(DIM)))
    };
    f.render_widget(Paragraph::new(st).alignment(Alignment::Right), a);
}

fn ping_cell(app: &App, id: &str) -> Span<'static> {
    if app.pending.contains(id) {
        return Span::styled("  ● PROBING", Style::new().fg(CYAN).bold());
    }
    match app.pings.get(id) {
        Some(Ping::Ms(ms)) => {
            let bars = if *ms < 60 {
                "▂▄▆█"
            } else if *ms < 150 {
                "▂▄▆ "
            } else if *ms < 300 {
                "▂▄  "
            } else {
                "▂   "
            };
            Span::styled(format!("{ms:>4}ms {bars}"), Style::new().fg(ms_color(*ms)).bold())
        }
        Some(Ping::Timeout) => Span::styled("  ✕ TIMEOUT", Style::new().fg(RED).bold()),
        None => Span::raw("   -- ms   "),
    }
}

fn profiles(f: &mut Frame, area: Rect, app: &mut App) {
    let mut title = format!("0x01 // TARGET NODES [ {} ]", app.view.len());
    if !app.filter.is_empty() {
        title = format!("0x01 // SCAN: {}█ [ {} MATCHES ]", trunc(&app.filter, 14), app.view.len());
    } else if app.sort_ping {
        title.push_str(" · ↑RTT");
    }
    if let Mode::Filter(s) = &app.mode {
        title = format!("0x01 // SCAN: {}█", trunc(s, 20));
    }
    let blk = block(&title);
    if app.view.is_empty() {
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        let msg = if app.profiles.is_empty() {
            vec![
                Line::from(""),
                Line::from(Span::styled("[!] NO TARGET TUNNELS CONFIGURED", Style::new().fg(YELLOW).bold())),
                Line::from(""),
                Line::from(Span::styled("  A  // INJECT LINK · SUBSCRIPTION · FILE", Style::new().fg(CYAN))),
                Line::from(Span::styled("  V  // INJECT TARGET FROM CLIPBOARD", Style::new().fg(DIM))),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled("[!] PATTERN SCAN: NO MATCHING TARGETS", Style::new().fg(RED).bold())),
                Line::from(Span::styled("  ESC // CLEAR SCAN FILTER", Style::new().fg(DIM))),
            ]
        };
        f.render_widget(Paragraph::new(msg).alignment(Alignment::Center), inner);
        return;
    }
    let w = (area.width as usize).saturating_sub(3);
    let active = app.session.as_ref().map(|s| s.id.clone());
    let items: Vec<ListItem> = app
        .view
        .iter()
        .enumerate()
        .map(|(idx, &i)| {
            let p = &app.profiles[i];
            let on = active.as_deref() == Some(p.id.as_str());
            let num = format!("{:02} ", idx + 1);
            let tag_str = format!("[{}]", p.kind.padded_tag());
            let fixed_w = 2 + 3 + 11 + 1 + 8; // marker(2) + num(3) + ping(11) + space(1) + tag(8) = 25
            let nw = w.saturating_sub(fixed_w).max(4);
            let name = trunc(&p.name, nw);
            let pad = nw.saturating_sub(name.chars().count());
            Line::from(vec![
                Span::styled(if on { "● " } else { "○ " }, Style::new().fg(if on { GREEN } else { DIM }).bold()),
                Span::styled(num, Style::new().fg(if on { GREEN } else { DIM })),
                Span::styled(name.into_owned(), Style::new().fg(if on { GREEN } else { FG }).bold()),
                Span::raw(spaces(pad + 1)),
                ping_cell(app, &p.id),
                Span::raw(" "),
                Span::styled(tag_str, Style::new().fg(kind_color(p.kind)).bold()),
            ])
            .into()
        })
        .collect();
    let list = List::new(items).block(blk).highlight_style(Style::new().bg(SEL_BG).fg(CYAN).bold()).highlight_symbol("► ");
    f.render_stateful_widget(list, area, &mut app.list);
}

fn kv<'a>(k: &str, v: impl Into<Cow<'a, str>>, c: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!(" {:<10} ", k.to_ascii_uppercase()), Style::new().fg(DIM).bold()),
        Span::styled("► ", Style::new().fg(BORDER)),
        Span::styled(v.into(), Style::new().fg(c).bold()),
    ])
}

fn spark(f: &mut Frame, r: Rect, data: &[u64], c: Color) {
    // Sparkline draws from the start of the slice, so hand it only the newest `width` samples
    let w = r.width as usize;
    let d = &data[data.len().saturating_sub(w)..];
    f.render_widget(Sparkline::default().data(d).style(Style::new().fg(c)), r);
}

fn info(f: &mut Frame, area: Rect, app: &App) {
    if app.show_log {
        let blk = block("0x04 // KERNEL AUDIT & CORE LOG");
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        let inner = inner.inner(Margin::new(2, 1));
        let lines: Vec<Line> = tunnel::tail_log(inner.height as usize)
            .into_iter()
            .map(|l| {
                let c = if l.contains("ERROR") || l.contains("FATAL") {
                    RED
                } else if l.contains("WARN") {
                    YELLOW
                } else if l.contains("connected") || l.contains("READY") || l.contains("success") {
                    GREEN
                } else {
                    DIM
                };
                Line::from(Span::styled(l, Style::new().fg(c)))
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
        f.render_widget(block("0x02 // ROUTE DISENGAGED"), area);
        return;
    };

    let parts = Layout::vertical([Constraint::Length(11), Constraint::Min(4)]).split(area);

    // ── connection card
    let blk = block("0x02 // TELEMETRY & ROUTE INSPECTOR");
    let inner = blk.inner(parts[0]).inner(Margin::new(2, 1));
    f.render_widget(blk, parts[0]);
    let nw = (inner.width as usize).saturating_sub(15);
    let mut lines = vec![];
    match &app.session {
        Some(s) => {
            lines.push(kv("status", "● ENGAGED // TUNNEL ACTIVE", GREEN));
            lines.push(kv("profile", trunc(&name, nw), FG));
            lines.push(kv("protocol", s.kind.tag(), kind_color(s.kind)));
            lines.push(kv("endpoint", trunc(&server, nw), FG));
            lines.push(kv("exit ip", if app.ip.is_empty() { "ANALYZING..." } else { &app.ip }, CYAN));
            lines.push(kv("uptime", fmt_dur(tunnel::now().saturating_sub(s.since)), FG));
            lines.push(match app.rtt {
                Some(ms) => kv("latency", format!("{ms} ms [REALTIME ICMP]"), ms_color(ms)),
                None => kv("latency", "PROBING...", DIM),
            });
        }
        None => {
            lines.push(kv("status", "○ STANDBY // ROUTE DISENGAGED", DIM));
            lines.push(kv("profile", trunc(&name, nw), FG));
            lines.push(kv("protocol", kind.tag(), kind_color(kind)));
            lines.push(kv("endpoint", trunc(&server, nw), FG));
            let id = sel.map(|p| p.id.as_str()).unwrap_or("");
            lines.push(match app.pings.get(id) {
                Some(Ping::Ms(ms)) => kv("probe rtt", format!("{ms} ms"), ms_color(*ms)),
                Some(Ping::Timeout) => kv("probe rtt", "UNREACHABLE / TIMEOUT", RED),
                None => kv("probe rtt", "NO TELEMETRY", DIM),
            });
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(" [⏎] ENGAGE  ", Style::new().fg(CYAN).bold()),
                Span::styled(" [T] PROBE  ", Style::new().fg(YELLOW).bold()),
                Span::styled(" [U] AUTH", Style::new().fg(DIM)),
            ]));
        }
    }
    f.render_widget(Paragraph::new(lines), inner);

    // ── traffic (connected) / details (idle)
    if let Some(_) = &app.session {
        let blk = block("0x03 // PACKET FLOW & JITTER ANALYZER");
        let inner = blk.inner(parts[1]).inner(Margin::new(2, 1));
        f.render_widget(blk, parts[1]);
        let rows = Layout::vertical([
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
        let line = Line::from(vec![
            Span::styled("RX ► ", Style::new().fg(CYAN).bold()),
            Span::styled(format!("{}/s", fmt_bytes(dn)), Style::new().fg(FG).bold()),
            Span::raw("   "),
            Span::styled("TX ▲ ", Style::new().fg(PURPLE).bold()),
            Span::styled(format!("{}/s", fmt_bytes(upn)), Style::new().fg(FG).bold()),
            Span::styled(format!("   │ CUMULATIVE: RX {} · TX {}", fmt_bytes(tot.0), fmt_bytes(tot.1)), Style::new().fg(DIM)),
        ]);
        f.render_widget(Paragraph::new(line), rows[0]);
        spark(f, rows[1], &app.down, CYAN);
        spark(f, rows[2], &app.up, PURPLE);
        let (lo, hi) = (app.rtt_hist.iter().min(), app.rtt_hist.iter().max());
        let rtt_txt = match (lo, hi) {
            (Some(l), Some(h)) => format!("RTT JITTER SPECTRUM   MIN {l}ms · MAX {h}ms"),
            _ => "RTT JITTER SPECTRUM".to_string(),
        };
        f.render_widget(Paragraph::new(Span::styled(rtt_txt, Style::new().fg(DIM).bold())), rows[3]);
        spark(f, rows[4], &app.rtt_hist, YELLOW);
    } else {
        let blk = block("0x03 // TARGET ENCRYPTED PARAMETERS");
        let inner = blk.inner(parts[1]).inner(Margin::new(2, 1));
        f.render_widget(blk, parts[1]);
        let lines: Vec<Line> = sel
            .map(store::details)
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| kv(k, trunc(&v, nw).into_owned(), FG))
            .collect();
        f.render_widget(Paragraph::new(lines), inner);
    }
}

fn footer(f: &mut Frame, a: Rect, app: &App) {
    if let Some((m, ok, _)) = &app.toast {
        let (tag, c) = if *ok {
            (" [✔ SYSTEM OK] ", GREEN)
        } else {
            (" [✕ BREACH/ERR] ", RED)
        };
        let text = format!("{tag}{}", trunc(m, (a.width as usize).saturating_sub(20)));
        f.render_widget(Paragraph::new(Span::styled(text, Style::new().fg(c).bold())), a);
        return;
    }
    let mut sp = vec![Span::styled(" root@vortex:~# ", Style::new().fg(GREEN).bold())];
    let keys = [
        ("RET", "ENGAGE"),
        ("SPC", "ABORT"),
        ("A", "INJECT"),
        ("T", "PROBE"),
        ("U", "AUTH"),
        ("/", "SCAN"),
        ("O", "SORT"),
        ("L", "LOG"),
        ("?", "HELP"),
        ("Q", "EXIT"),
    ];
    for (k, d) in keys {
        sp.push(Span::styled(format!("[{k}]"), Style::new().fg(CYAN).bold()));
        sp.push(Span::styled(format!(" {d}  "), Style::new().fg(DIM)));
    }
    f.render_widget(Paragraph::new(Line::from(sp)), a);
}

fn popup(f: &mut Frame, area: Rect, title: &str, hint: &str, input: &str) {
    let w = area.width.min(78);
    let h = 5.min(area.height);
    let r = Rect { x: area.x + (area.width - w) / 2, y: area.y + area.height.saturating_sub(h) / 2, width: w, height: h };
    f.render_widget(Clear, r);
    let blk = block(title);
    let inner = blk.inner(r);
    f.render_widget(blk, r);
    let max = (inner.width as usize).saturating_sub(24);
    let n = input.chars().count();
    let shown: String = input.chars().skip(n.saturating_sub(max)).collect();
    let lines = vec![
        Line::from(Span::styled(format!(" ⌁ {hint}"), Style::new().fg(DIM))),
        Line::from(""),
        Line::from(vec![
            Span::styled(" root@vortex:input# ", Style::new().fg(GREEN).bold()),
            Span::styled(shown, Style::new().fg(FG).bold()),
            Span::styled("█", Style::new().fg(CYAN)),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn help(f: &mut Frame, area: Rect) {
    let rows: [(&str, &str); 17] = [
        ("RET / ENTER", "ENGAGE SELECTED TARGET"),
        ("SPC / S", "ABORT / DISENGAGE TUNNEL"),
        ("J K ↑ ↓", "NAVIGATE TARGET MATRIX"),
        ("G / SHIFT+G", "JUMP TO TOP / BOTTOM"),
        ("A", "INJECT LINK / SUB / FILE"),
        ("V", "INJECT FROM SYSTEM CLIPBOARD"),
        ("/", "PATTERN SCAN / FILTER"),
        ("T / SHIFT+T", "PROBE LATENCY: ALL / TARGET"),
        ("O", "CYCLE SORT ORDER (RTT ⇄ ID)"),
        ("U", "CONFIGURE OPENVPN CREDENTIALS"),
        ("R", "RENAME TARGET IDENTIFIER"),
        ("D", "DELETE TARGET FROM MATRIX"),
        ("L", "TOGGLE KERNEL AUDIT & LOGS"),
        ("I", "PROBE LIVE EXIT IP"),
        ("ESC", "ABORT / DISMISS / CLEAR SCAN"),
        ("Q", "DETACH CONSOLE (TUNNEL PERSISTS)"),
        ("SHIFT+Q", "TERMINATE CONSOLE & DISCONNECT"),
    ];
    let h = (rows.len() as u16 + 4).min(area.height);
    let w = 58.min(area.width);
    let r = Rect { x: area.x + (area.width - w) / 2, y: area.y + area.height.saturating_sub(h) / 2, width: w, height: h };
    f.render_widget(Clear, r);
    let blk = block("0x?? // CYBER COMMAND DIRECTORY");
    let inner = blk.inner(r).inner(Margin::new(2, 1));
    f.render_widget(blk, r);
    let lines: Vec<Line> = rows
        .iter()
        .map(|(k, d)| {
            Line::from(vec![
                Span::styled(format!(" [{k:<11}] "), Style::new().fg(CYAN).bold()),
                Span::styled("► ", Style::new().fg(BORDER)),
                Span::styled(*d, Style::new().fg(FG)),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn prof(id: &str, name: &str, kind: Kind, data: &str) -> Profile {
        Profile { id: id.into(), name: name.into(), kind, server: "203.0.113.7:443".into(), data: data.into(), auth: None }
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
}
