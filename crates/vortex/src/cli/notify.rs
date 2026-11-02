use std::process::Command;

pub fn which_exists(binary: &str) -> bool {
    Command::new("which")
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn send_notification(summary: &str, body: &str, icon: Option<&str>) {
    let mut cmd = Command::new("notify-send");
    cmd.arg("-a").arg("Vortex");
    cmd.arg("-t").arg("3000");
    if let Some(i) = icon {
        cmd.arg("-i").arg(i);
    }
    cmd.arg(summary).arg(body);
    let _ = cmd.status();
}
