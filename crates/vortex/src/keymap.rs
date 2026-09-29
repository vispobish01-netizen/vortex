use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfirmKind {
    DeleteNode,
    QuitWhileConnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search(String),
    Confirm(ConfirmKind),
    Help,
    Add(String),
    Edit(String),
    Qr,
    Subs,
    Recon,
    Speed,
    Rules,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    // Navigation
    NextNode,
    PrevNode,
    FirstNode,
    LastNode,
    FocusNextPanel,
    FocusPanel(usize),
    EnterSearch,

    // Connection
    ConnectSelected,
    ToggleConnection,
    Reconnect,
    ToggleShield,

    // Nodes
    AddNode,
    EditNode,
    DeleteNode,
    CopyConfig,
    ShowQr,
    CycleSort,

    // Testing
    TestSelected,
    TestAll,
    SpeedTest,

    // Subscriptions
    UpdateSubs,
    ManageSubs,

    // Views
    ToggleFlows,
    ToggleLog,
    ShowIpInfo,

    // General
    Help,
    Quit,
    ForceQuit,
    Cancel,

    // Confirmation & Input
    ConfirmYes,
    ConfirmNo,
    ConfirmBackground,
    InputChar(char),
    Backspace,
    ClearInput,
    Submit,

    // Retained features
    ManageAuth,
    PasteClipboard,

    // Modal sub-actions
    ExportConfig,
    NextSub,
    PrevSub,
    SyncSelectedSub,
    DeleteSub,
    RetryProbe,
    RetrySpeedTest,
    ManageRules,
    ToggleRule,
}

impl Action {
    pub fn as_snake_case(&self) -> &'static str {
        match self {
            Action::ManageRules => "manage_rules",
            Action::ToggleRule => "toggle_rule",
            Action::NextNode => "next_node",
            Action::PrevNode => "prev_node",
            Action::FirstNode => "first_node",
            Action::LastNode => "last_node",
            Action::FocusNextPanel => "focus_next_panel",
            Action::FocusPanel(1) => "focus_panel_1",
            Action::FocusPanel(2) => "focus_panel_2",
            Action::FocusPanel(3) => "focus_panel_3",
            Action::FocusPanel(_) => "focus_panel",
            Action::EnterSearch => "enter_search",
            Action::ConnectSelected => "connect_selected",
            Action::ToggleConnection => "toggle_connection",
            Action::Reconnect => "reconnect",
            Action::ToggleShield => "toggle_shield",
            Action::AddNode => "add_node",
            Action::EditNode => "edit_node",
            Action::DeleteNode => "delete_node",
            Action::CopyConfig => "copy_config",
            Action::ShowQr => "show_qr",
            Action::CycleSort => "cycle_sort",
            Action::TestSelected => "test_selected",
            Action::TestAll => "test_all",
            Action::SpeedTest => "speed_test",
            Action::UpdateSubs => "update_subs",
            Action::ManageSubs => "manage_subs",
            Action::ToggleFlows => "toggle_flows",
            Action::ToggleLog => "toggle_log",
            Action::ShowIpInfo => "show_ip_info",
            Action::Help => "help",
            Action::Quit => "quit",
            Action::ForceQuit => "force_quit",
            Action::Cancel => "cancel",
            Action::ConfirmYes => "confirm_yes",
            Action::ConfirmNo => "confirm_no",
            Action::ConfirmBackground => "confirm_background",
            Action::InputChar(_) => "input_char",
            Action::Backspace => "backspace",
            Action::ClearInput => "clear_input",
            Action::Submit => "submit",
            Action::ManageAuth => "manage_auth",
            Action::PasteClipboard => "paste_clipboard",
            Action::ExportConfig => "export_config",
            Action::NextSub => "next_sub",
            Action::PrevSub => "prev_sub",
            Action::SyncSelectedSub => "sync_selected_sub",
            Action::DeleteSub => "delete_sub",
            Action::RetryProbe => "retry_probe",
            Action::RetrySpeedTest => "retry_speed_test",
        }
    }

    pub fn from_snake_case(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "next_node" => Some(Action::NextNode),
            "prev_node" => Some(Action::PrevNode),
            "first_node" => Some(Action::FirstNode),
            "last_node" => Some(Action::LastNode),
            "focus_next_panel" => Some(Action::FocusNextPanel),
            "focus_panel_1" | "focus_panel1" => Some(Action::FocusPanel(1)),
            "focus_panel_2" | "focus_panel2" => Some(Action::FocusPanel(2)),
            "focus_panel_3" | "focus_panel3" => Some(Action::FocusPanel(3)),
            "enter_search" | "search" => Some(Action::EnterSearch),
            "connect_selected" | "connect" => Some(Action::ConnectSelected),
            "toggle_connection" => Some(Action::ToggleConnection),
            "reconnect" => Some(Action::Reconnect),
            "toggle_shield" | "shield" => Some(Action::ToggleShield),
            "add_node" | "add" => Some(Action::AddNode),
            "edit_node" | "edit" => Some(Action::EditNode),
            "delete_node" | "delete" => Some(Action::DeleteNode),
            "copy_config" | "copy" => Some(Action::CopyConfig),
            "show_qr" | "qr" => Some(Action::ShowQr),
            "cycle_sort" | "sort" => Some(Action::CycleSort),
            "test_selected" | "test" => Some(Action::TestSelected),
            "test_all" => Some(Action::TestAll),
            "speed_test" | "speed" => Some(Action::SpeedTest),
            "update_subs" => Some(Action::UpdateSubs),
            "manage_subs" | "subs" => Some(Action::ManageSubs),
            "toggle_flows" | "flows" => Some(Action::ToggleFlows),
            "toggle_log" | "log" => Some(Action::ToggleLog),
            "show_ip_info" | "ip_info" | "recon" => Some(Action::ShowIpInfo),
            "help" => Some(Action::Help),
            "quit" => Some(Action::Quit),
            "force_quit" => Some(Action::ForceQuit),
            "cancel" => Some(Action::Cancel),
            "confirm_yes" => Some(Action::ConfirmYes),
            "confirm_no" => Some(Action::ConfirmNo),
            "confirm_background" => Some(Action::ConfirmBackground),
            "backspace" => Some(Action::Backspace),
            "clear_input" => Some(Action::ClearInput),
            "submit" => Some(Action::Submit),
            "manage_auth" | "auth" => Some(Action::ManageAuth),
            "paste_clipboard" | "paste" => Some(Action::PasteClipboard),
            "export_config" => Some(Action::ExportConfig),
            "next_sub" => Some(Action::NextSub),
            "prev_sub" => Some(Action::PrevSub),
            "sync_selected_sub" => Some(Action::SyncSelectedSub),
            "delete_sub" => Some(Action::DeleteSub),
            "retry_probe" => Some(Action::RetryProbe),
            "retry_speed_test" => Some(Action::RetrySpeedTest),
            "manage_rules" | "rules" => Some(Action::ManageRules),
            "toggle_rule" => Some(Action::ToggleRule),
            _ => None,
        }
    }
}

impl Serialize for Action {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_snake_case())
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Action::from_snake_case(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown action: {s}")))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KeyHelp {
    pub category: &'static str,
    pub key: &'static str,
    pub description: &'static str,
    #[allow(dead_code)]
    pub action: Action,
}

pub const HELP_ENTRIES: &[KeyHelp] = &[
    // Navigation
    KeyHelp {
        category: "NAVIGATION",
        key: "j / ↓",
        description: "Next node in matrix",
        action: Action::NextNode,
    },
    KeyHelp {
        category: "NAVIGATION",
        key: "k / ↑",
        description: "Previous node in matrix",
        action: Action::PrevNode,
    },
    KeyHelp {
        category: "NAVIGATION",
        key: "g / Home",
        description: "Jump to first node",
        action: Action::FirstNode,
    },
    KeyHelp {
        category: "NAVIGATION",
        key: "G / End",
        description: "Jump to last node",
        action: Action::LastNode,
    },
    KeyHelp {
        category: "NAVIGATION",
        key: "Tab",
        description: "Cycle focus between panels",
        action: Action::FocusNextPanel,
    },
    KeyHelp {
        category: "NAVIGATION",
        key: "1 / 2 / 3",
        description: "Direct focus panel [1] / [2] / [3]",
        action: Action::FocusPanel(1),
    },
    KeyHelp {
        category: "NAVIGATION",
        key: "/",
        description: "Search nodes (live filtering)",
        action: Action::EnterSearch,
    },
    // Connection
    KeyHelp {
        category: "CONNECTION",
        key: "Enter",
        description: "Connect to selected / switch node",
        action: Action::ConnectSelected,
    },
    KeyHelp {
        category: "CONNECTION",
        key: "Space",
        description: "Toggle connect / disconnect",
        action: Action::ToggleConnection,
    },
    KeyHelp {
        category: "CONNECTION",
        key: "r",
        description: "Reconnect tunnel",
        action: Action::Reconnect,
    },
    KeyHelp {
        category: "CONNECTION",
        key: "K (Shift+k)",
        description: "Toggle stealth shield / kill-switch",
        action: Action::ToggleShield,
    },
    // Nodes
    KeyHelp {
        category: "NODES",
        key: "a",
        description: "Add config (link / sub / file)",
        action: Action::AddNode,
    },
    KeyHelp {
        category: "NODES",
        key: "e",
        description: "Edit / rename selected node",
        action: Action::EditNode,
    },
    KeyHelp {
        category: "NODES",
        key: "d",
        description: "Delete node (y/n confirm prompt)",
        action: Action::DeleteNode,
    },
    KeyHelp {
        category: "NODES",
        key: "y",
        description: "Copy config link to clipboard",
        action: Action::CopyConfig,
    },
    KeyHelp {
        category: "NODES",
        key: "s",
        description: "Show QR code / share payload",
        action: Action::ShowQr,
    },
    KeyHelp {
        category: "NODES",
        key: "o",
        description: "Cycle sort mode (RTT / name / proto)",
        action: Action::CycleSort,
    },
    KeyHelp {
        category: "NODES",
        key: "c",
        description: "Configure OpenVPN credentials vault",
        action: Action::ManageAuth,
    },
    KeyHelp {
        category: "NODES",
        key: "v",
        description: "Paste config / QR from clipboard",
        action: Action::PasteClipboard,
    },
    // Testing
    KeyHelp {
        category: "TESTING",
        key: "t",
        description: "Test latency of selected node",
        action: Action::TestSelected,
    },
    KeyHelp {
        category: "TESTING",
        key: "T (Shift+t)",
        description: "Test latency of all nodes",
        action: Action::TestAll,
    },
    KeyHelp {
        category: "TESTING",
        key: "w",
        description: "Measure speed & bandwidth throughput",
        action: Action::SpeedTest,
    },
    // Subscriptions
    KeyHelp {
        category: "SUBSCRIPTIONS",
        key: "u",
        description: "Update all subscriptions",
        action: Action::UpdateSubs,
    },
    KeyHelp {
        category: "SUBSCRIPTIONS",
        key: "S (Shift+s)",
        description: "Manage subscription endpoints",
        action: Action::ManageSubs,
    },
    // Views
    KeyHelp {
        category: "VIEWS",
        key: "f",
        description: "Toggle active socket flows sniffer",
        action: Action::ToggleFlows,
    },
    KeyHelp {
        category: "VIEWS",
        key: "l",
        description: "Toggle kernel audit & core logs",
        action: Action::ToggleLog,
    },
    KeyHelp {
        category: "VIEWS",
        key: "i",
        description: "IP info / deep recon & leak check",
        action: Action::ShowIpInfo,
    },
    // General
    KeyHelp {
        category: "GENERAL",
        key: "?",
        description: "Open command directory & help",
        action: Action::Help,
    },
    KeyHelp {
        category: "GENERAL",
        key: "q",
        description: "Quit (safe confirm if connected)",
        action: Action::Quit,
    },
    KeyHelp {
        category: "GENERAL",
        key: "Esc",
        description: "Close popup / dismiss / clear filter",
        action: Action::Cancel,
    },
];

pub fn parse_key_spec(s: &str) -> Option<(KeyCode, KeyModifiers)> {
    let raw = s.trim();
    if raw.is_empty() {
        return None;
    }
    let lower = raw.to_lowercase();
    let mut mods = KeyModifiers::NONE;
    let main_part = if lower.starts_with("ctrl+") || lower.starts_with("c-") {
        mods |= KeyModifiers::CONTROL;
        let prefix_len = if lower.starts_with("ctrl+") { 5 } else { 2 };
        &raw[prefix_len..]
    } else if lower.starts_with("alt+") || lower.starts_with("a-") {
        mods |= KeyModifiers::ALT;
        let prefix_len = if lower.starts_with("alt+") { 4 } else { 2 };
        &raw[prefix_len..]
    } else if lower.starts_with("shift+") || lower.starts_with("s-") {
        mods |= KeyModifiers::SHIFT;
        let prefix_len = if lower.starts_with("shift+") { 6 } else { 2 };
        &raw[prefix_len..]
    } else {
        raw
    };

    let main_lower = main_part.to_lowercase();
    let code = match main_lower.as_str() {
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" | "pgup" => KeyCode::PageUp,
        "pagedown" | "pgdn" => KeyCode::PageDown,
        "tab" => KeyCode::Tab,
        "enter" | "return" => KeyCode::Enter,
        "space" | "spc" => KeyCode::Char(' '),
        "esc" | "escape" => KeyCode::Esc,
        "backspace" => KeyCode::Backspace,
        _ => {
            let mut chars = main_part.chars();
            let first = chars.next()?;
            if chars.next().is_none() {
                if first.is_ascii_uppercase() {
                    mods |= KeyModifiers::SHIFT;
                }
                KeyCode::Char(first)
            } else {
                return None;
            }
        }
    };
    Some((code, mods))
}

fn user_config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("VORTEX_KEYS_CONFIG") {
        return Some(PathBuf::from(p));
    }
    if let Ok(home) = std::env::var("HOME") {
        Some(PathBuf::from(home).join(".config/vortex/keys.toml"))
    } else {
        None
    }
}

fn load_overrides() -> HashMap<(KeyCode, KeyModifiers), Action> {
    let mut map = HashMap::new();
    let Some(path) = user_config_path() else {
        return map;
    };
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return map,
    };
    let parsed: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return map,
    };

    let mut process_table = |tbl: &toml::map::Map<String, toml::Value>| {
        for (k, v) in tbl {
            let val_str = match v {
                toml::Value::String(s) => s.as_str(),
                _ => continue,
            };
            // Try k = action, val = key
            if let Some(act) = Action::from_snake_case(k) {
                if let Some((code, mods)) = parse_key_spec(val_str) {
                    map.insert((code, mods), act);
                    continue;
                }
            }
            // Try k = key, val = action
            if let Some(act) = Action::from_snake_case(val_str) {
                if let Some((code, mods)) = parse_key_spec(k) {
                    map.insert((code, mods), act);
                }
            }
        }
    };

    if let toml::Value::Table(tbl) = parsed {
        process_table(&tbl);
        if let Some(toml::Value::Table(sub_tbl)) = tbl.get("keys").or_else(|| tbl.get("bindings")) {
            process_table(sub_tbl);
        }
    }
    map
}

fn user_overrides() -> &'static HashMap<(KeyCode, KeyModifiers), Action> {
    static OVERRIDES: OnceLock<HashMap<(KeyCode, KeyModifiers), Action>> = OnceLock::new();
    OVERRIDES.get_or_init(load_overrides)
}

pub fn map_key(mode: &Mode, key: KeyEvent) -> Option<Action> {
    if key.kind != KeyEventKind::Press {
        return None;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Some(Action::ForceQuit);
    }

    match mode {
        Mode::Normal => {
            let overrides = user_overrides();
            if let Some(&action) = overrides.get(&(key.code, key.modifiers)) {
                return Some(action);
            }
            if let KeyCode::Char(c) = key.code {
                if let Some(&action) = overrides.get(&(KeyCode::Char(c), KeyModifiers::NONE)) {
                    return Some(action);
                }
            }

            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            let shift = key.modifiers.contains(KeyModifiers::SHIFT);

            match key.code {
                KeyCode::Char('c') if ctrl => Some(Action::ForceQuit),
                KeyCode::Char('j') | KeyCode::Down => Some(Action::NextNode),
                KeyCode::Char('k') if !shift => Some(Action::PrevNode),
                KeyCode::Up => Some(Action::PrevNode),
                KeyCode::Char('g') if !shift => Some(Action::FirstNode),
                KeyCode::Home => Some(Action::FirstNode),
                KeyCode::Char('G') | KeyCode::End => Some(Action::LastNode),
                KeyCode::Char('g') if shift => Some(Action::LastNode),
                KeyCode::Tab => Some(Action::FocusNextPanel),
                KeyCode::Char('1') => Some(Action::FocusPanel(1)),
                KeyCode::Char('2') => Some(Action::FocusPanel(2)),
                KeyCode::Char('3') => Some(Action::FocusPanel(3)),
                KeyCode::Char('/') => Some(Action::EnterSearch),
                KeyCode::Enter => Some(Action::ConnectSelected),
                KeyCode::Char(' ') => Some(Action::ToggleConnection),
                KeyCode::Char('r') if !shift => Some(Action::Reconnect),
                KeyCode::Char('R') => Some(Action::ManageRules),
                KeyCode::Char('r') if shift => Some(Action::ManageRules),
                KeyCode::Char('K') => Some(Action::ToggleShield),
                KeyCode::Char('k') if shift => Some(Action::ToggleShield),
                KeyCode::Char('a') if !shift => Some(Action::AddNode),
                KeyCode::Char('e') => Some(Action::EditNode),
                KeyCode::Char('d') => Some(Action::DeleteNode),
                KeyCode::Char('y') => Some(Action::CopyConfig),
                KeyCode::Char('s') if !shift => Some(Action::ShowQr),
                KeyCode::Char('o') => Some(Action::CycleSort),
                KeyCode::Char('t') if !shift => Some(Action::TestSelected),
                KeyCode::Char('T') => Some(Action::TestAll),
                KeyCode::Char('t') if shift => Some(Action::TestAll),
                KeyCode::Char('w') => Some(Action::SpeedTest),
                KeyCode::Char('u') => Some(Action::UpdateSubs),
                KeyCode::Char('S') => Some(Action::ManageSubs),
                KeyCode::Char('s') if shift => Some(Action::ManageSubs),
                KeyCode::Char('f') => Some(Action::ToggleFlows),
                KeyCode::Char('l') => Some(Action::ToggleLog),
                KeyCode::Char('i') => Some(Action::ShowIpInfo),
                KeyCode::Char('?') => Some(Action::Help),
                KeyCode::Char('q') => Some(Action::Quit),
                KeyCode::Esc => Some(Action::Cancel),
                KeyCode::Char('c') if !ctrl => Some(Action::ManageAuth),
                KeyCode::Char('v') => Some(Action::PasteClipboard),
                _ => None,
            }
        }
        Mode::Search(_) => {
            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Esc => Some(Action::Cancel),
                KeyCode::Enter => Some(Action::Submit),
                KeyCode::Backspace => Some(Action::Backspace),
                KeyCode::Char('u') if ctrl => Some(Action::ClearInput),
                KeyCode::Char('w') if ctrl => Some(Action::ClearInput),
                KeyCode::Char(c) if !ctrl => Some(Action::InputChar(c)),
                _ => None,
            }
        }
        Mode::Confirm(kind) => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => Some(Action::ConfirmYes),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => Some(Action::ConfirmNo),
            KeyCode::Char('b') | KeyCode::Char('B') if *kind == ConfirmKind::QuitWhileConnected => {
                Some(Action::ConfirmBackground)
            }
            _ => None,
        },
        Mode::Help => match key.code {
            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Enter => {
                Some(Action::Cancel)
            }
            _ => None,
        },
        Mode::Add(_) => {
            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Esc => Some(Action::Cancel),
                KeyCode::Enter => Some(Action::Submit),
                KeyCode::Backspace => Some(Action::Backspace),
                KeyCode::Char('u') if ctrl => Some(Action::ClearInput),
                KeyCode::Char('w') if ctrl => Some(Action::ClearInput),
                KeyCode::Char(c) if !ctrl => Some(Action::InputChar(c)),
                _ => None,
            }
        }
        Mode::Edit(_) => {
            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Esc => Some(Action::Cancel),
                KeyCode::Enter => Some(Action::Submit),
                KeyCode::Backspace => Some(Action::Backspace),
                KeyCode::Char('u') if ctrl => Some(Action::ClearInput),
                KeyCode::Char('w') if ctrl => Some(Action::ClearInput),
                KeyCode::Char(c) if !ctrl => Some(Action::InputChar(c)),
                _ => None,
            }
        }
        Mode::Qr => match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Some(Action::Cancel),
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Char('c') | KeyCode::Char('C') => {
                Some(Action::CopyConfig)
            }
            KeyCode::Char('s') | KeyCode::Char('S') | KeyCode::Char('e') | KeyCode::Char('E') => {
                Some(Action::ExportConfig)
            }
            _ => None,
        },
        Mode::Subs => match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Some(Action::Cancel),
            KeyCode::Char('j') | KeyCode::Down => Some(Action::NextSub),
            KeyCode::Char('k') | KeyCode::Up => Some(Action::PrevSub),
            KeyCode::Enter | KeyCode::Char('u') => Some(Action::SyncSelectedSub),
            KeyCode::Char('s') | KeyCode::Char('S') => Some(Action::UpdateSubs),
            KeyCode::Char('a') => Some(Action::AddNode),
            KeyCode::Char('d') => Some(Action::DeleteSub),
            _ => None,
        },
        Mode::Recon => match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => Some(Action::Cancel),
            KeyCode::Char('r') | KeyCode::Char('R') => Some(Action::RetryProbe),
            _ => None,
        },
        Mode::Speed => match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Some(Action::Cancel),
            KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Enter => {
                Some(Action::RetrySpeedTest)
            }
            _ => None,
        },
        Mode::Rules => match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Some(Action::Cancel),
            KeyCode::Char('j') | KeyCode::Down => Some(Action::NextNode),
            KeyCode::Char('k') | KeyCode::Up => Some(Action::PrevNode),
            KeyCode::Char(' ') | KeyCode::Enter => Some(Action::ToggleRule),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn press_shift(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::SHIFT)
    }

    fn press_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn test_release_and_repeat_events_ignored() {
        let mut key = KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE);
        key.kind = KeyEventKind::Release;
        assert_eq!(map_key(&Mode::Normal, key), None);

        key.kind = KeyEventKind::Repeat;
        assert_eq!(map_key(&Mode::Normal, key), None);
    }

    #[test]
    fn test_ctrl_c_force_quit_in_every_mode() {
        let modes = [
            Mode::Normal,
            Mode::Search("test".into()),
            Mode::Confirm(ConfirmKind::DeleteNode),
            Mode::Confirm(ConfirmKind::QuitWhileConnected),
            Mode::Help,
            Mode::Add("payload".into()),
            Mode::Edit("alias".into()),
            Mode::Qr,
            Mode::Subs,
            Mode::Recon,
            Mode::Speed,
            Mode::Rules,
        ];
        for mode in &modes {
            assert_eq!(
                map_key(mode, press_ctrl(KeyCode::Char('c'))),
                Some(Action::ForceQuit),
                "Failed ForceQuit check in mode {:?}",
                mode
            );
        }
    }

    #[test]
    fn test_normal_mode_navigation() {
        let m = Mode::Normal;
        assert_eq!(
            map_key(&m, press(KeyCode::Char('j'))),
            Some(Action::NextNode)
        );
        assert_eq!(map_key(&m, press(KeyCode::Down)), Some(Action::NextNode));
        assert_eq!(
            map_key(&m, press(KeyCode::Char('k'))),
            Some(Action::PrevNode)
        );
        assert_eq!(map_key(&m, press(KeyCode::Up)), Some(Action::PrevNode));
        assert_eq!(
            map_key(&m, press(KeyCode::Char('g'))),
            Some(Action::FirstNode)
        );
        assert_eq!(map_key(&m, press(KeyCode::Home)), Some(Action::FirstNode));
        assert_eq!(
            map_key(&m, press(KeyCode::Char('G'))),
            Some(Action::LastNode)
        );
        assert_eq!(
            map_key(&m, press_shift(KeyCode::Char('g'))),
            Some(Action::LastNode)
        );
        assert_eq!(map_key(&m, press(KeyCode::End)), Some(Action::LastNode));
        assert_eq!(
            map_key(&m, press(KeyCode::Tab)),
            Some(Action::FocusNextPanel)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('1'))),
            Some(Action::FocusPanel(1))
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('2'))),
            Some(Action::FocusPanel(2))
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('3'))),
            Some(Action::FocusPanel(3))
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('/'))),
            Some(Action::EnterSearch)
        );
    }

    #[test]
    fn test_normal_mode_connection() {
        let m = Mode::Normal;
        assert_eq!(
            map_key(&m, press(KeyCode::Enter)),
            Some(Action::ConnectSelected)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char(' '))),
            Some(Action::ToggleConnection)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('r'))),
            Some(Action::Reconnect)
        );

        // Uppercase K for Shield, lowercase k is previous node!
        assert_eq!(
            map_key(&m, press(KeyCode::Char('K'))),
            Some(Action::ToggleShield)
        );
        assert_eq!(
            map_key(&m, press_shift(KeyCode::Char('k'))),
            Some(Action::ToggleShield)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('k'))),
            Some(Action::PrevNode)
        );
    }

    #[test]
    fn test_normal_mode_nodes() {
        let m = Mode::Normal;
        assert_eq!(
            map_key(&m, press(KeyCode::Char('a'))),
            Some(Action::AddNode)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('e'))),
            Some(Action::EditNode)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('d'))),
            Some(Action::DeleteNode)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('y'))),
            Some(Action::CopyConfig)
        );
        assert_eq!(map_key(&m, press(KeyCode::Char('s'))), Some(Action::ShowQr));
        assert_eq!(
            map_key(&m, press(KeyCode::Char('o'))),
            Some(Action::CycleSort)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('c'))),
            Some(Action::ManageAuth)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('v'))),
            Some(Action::PasteClipboard)
        );
    }

    #[test]
    fn test_normal_mode_testing() {
        let m = Mode::Normal;
        assert_eq!(
            map_key(&m, press(KeyCode::Char('t'))),
            Some(Action::TestSelected)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('T'))),
            Some(Action::TestAll)
        );
        assert_eq!(
            map_key(&m, press_shift(KeyCode::Char('t'))),
            Some(Action::TestAll)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('w'))),
            Some(Action::SpeedTest)
        );
    }

    #[test]
    fn test_normal_mode_subs_and_views() {
        let m = Mode::Normal;
        assert_eq!(
            map_key(&m, press(KeyCode::Char('u'))),
            Some(Action::UpdateSubs)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('S'))),
            Some(Action::ManageSubs)
        );
        assert_eq!(
            map_key(&m, press_shift(KeyCode::Char('s'))),
            Some(Action::ManageSubs)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('f'))),
            Some(Action::ToggleFlows)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('l'))),
            Some(Action::ToggleLog)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('i'))),
            Some(Action::ShowIpInfo)
        );
    }

    #[test]
    fn test_normal_mode_general() {
        let m = Mode::Normal;
        assert_eq!(map_key(&m, press(KeyCode::Char('?'))), Some(Action::Help));
        assert_eq!(map_key(&m, press(KeyCode::Char('q'))), Some(Action::Quit));
        assert_eq!(map_key(&m, press(KeyCode::Esc)), Some(Action::Cancel));
    }

    #[test]
    fn test_search_mode() {
        let m = Mode::Search("vless".into());
        assert_eq!(
            map_key(&m, press(KeyCode::Char('x'))),
            Some(Action::InputChar('x'))
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Backspace)),
            Some(Action::Backspace)
        );
        assert_eq!(map_key(&m, press(KeyCode::Enter)), Some(Action::Submit));
        assert_eq!(map_key(&m, press(KeyCode::Esc)), Some(Action::Cancel));
        assert_eq!(
            map_key(&m, press_ctrl(KeyCode::Char('u'))),
            Some(Action::ClearInput)
        );
    }

    #[test]
    fn test_confirm_mode_delete() {
        let m = Mode::Confirm(ConfirmKind::DeleteNode);
        assert_eq!(
            map_key(&m, press(KeyCode::Char('y'))),
            Some(Action::ConfirmYes)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('Y'))),
            Some(Action::ConfirmYes)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('n'))),
            Some(Action::ConfirmNo)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('N'))),
            Some(Action::ConfirmNo)
        );
        assert_eq!(map_key(&m, press(KeyCode::Esc)), Some(Action::ConfirmNo));
        // 'b' is not allowed for DeleteNode
        assert_eq!(map_key(&m, press(KeyCode::Char('b'))), None);
    }

    #[test]
    fn test_confirm_mode_quit_connected() {
        let m = Mode::Confirm(ConfirmKind::QuitWhileConnected);
        assert_eq!(
            map_key(&m, press(KeyCode::Char('y'))),
            Some(Action::ConfirmYes)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('n'))),
            Some(Action::ConfirmNo)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('b'))),
            Some(Action::ConfirmBackground)
        );
        assert_eq!(
            map_key(&m, press(KeyCode::Char('B'))),
            Some(Action::ConfirmBackground)
        );
        assert_eq!(map_key(&m, press(KeyCode::Esc)), Some(Action::ConfirmNo));
    }

    #[test]
    fn test_help_mode() {
        let m = Mode::Help;
        assert_eq!(map_key(&m, press(KeyCode::Esc)), Some(Action::Cancel));
        assert_eq!(map_key(&m, press(KeyCode::Char('?'))), Some(Action::Cancel));
        assert_eq!(map_key(&m, press(KeyCode::Char('q'))), Some(Action::Cancel));
    }

    #[test]
    fn test_modal_modes_esc_returns_cancel() {
        let modes = [
            Mode::Add("".into()),
            Mode::Edit("".into()),
            Mode::Qr,
            Mode::Subs,
            Mode::Recon,
            Mode::Speed,
        ];
        for mode in &modes {
            assert_eq!(map_key(mode, press(KeyCode::Esc)), Some(Action::Cancel));
        }
    }

    #[test]
    fn test_parse_key_spec() {
        assert_eq!(
            parse_key_spec("j"),
            Some((KeyCode::Char('j'), KeyModifiers::NONE))
        );
        assert_eq!(
            parse_key_spec("K"),
            Some((KeyCode::Char('K'), KeyModifiers::SHIFT))
        );
        assert_eq!(
            parse_key_spec("down"),
            Some((KeyCode::Down, KeyModifiers::NONE))
        );
        assert_eq!(
            parse_key_spec("ctrl+c"),
            Some((KeyCode::Char('c'), KeyModifiers::CONTROL))
        );
        assert_eq!(
            parse_key_spec("shift+k"),
            Some((KeyCode::Char('k'), KeyModifiers::SHIFT))
        );
    }
}
