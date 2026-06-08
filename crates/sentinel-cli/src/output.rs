use colored::Colorize;

pub fn success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg);
}

pub fn error(msg: &str) {
    eprintln!("{} {}", "✗".red().bold(), msg);
}

pub fn warning(msg: &str) {
    eprintln!("{} {}", "⚠".yellow().bold(), msg);
}

pub fn info(msg: &str) {
    println!("{} {}", "ℹ".blue().bold(), msg);
}

pub fn header(msg: &str) {
    println!("{}", msg.bold());
    println!("{}", "─".repeat(msg.len()).dimmed());
}

pub fn json(value: &serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
}

pub fn separator() {
    println!("{}", "─".repeat(60).dimmed());
}

pub fn status_badge(status: &str) -> colored::ColoredString {
    match status {
        "active" | "running" | "allowed" => status.green().bold(),
        "blocked" | "banned" | "rejected" => status.red().bold(),
        "warning" | "suspicious" => status.yellow().bold(),
        _ => status.white(),
    }
}

pub fn severity_badge(severity: &str) -> colored::ColoredString {
    match severity.to_lowercase().as_str() {
        "critical" => severity.red().bold(),
        "high" => severity.bright_red(),
        "medium" => severity.yellow(),
        "low" => severity.blue(),
        _ => severity.white(),
    }
}

pub fn ip_display(ip: &str) -> colored::ColoredString {
    ip.cyan().bold()
}
