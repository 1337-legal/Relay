//! Timestamped, colored console logging.

use chrono::{Local, Timelike};
use colored::Colorize;

fn format_console_date() -> String {
    let now = Local::now();
    format!(
        "[{:02}:{:02}:{:02}.{:03}] ",
        now.hour(),
        now.minute(),
        now.second(),
        now.timestamp_subsec_millis(),
    )
}

fn timestamp(text: &str) -> colored::ColoredString {
    text.truecolor(0xd6, 0xaf, 0x42)
}

pub fn info(message: impl std::fmt::Display) {
    println!("{}{}{}", timestamp(&format_console_date()), "[INFO] ".cyan(), message);
}

pub fn error(message: impl std::fmt::Display) {
    eprintln!("{}{}{}", timestamp(&format_console_date()), "[ERROR] ".red(), message);
}

pub fn success(message: impl std::fmt::Display) {
    println!("{}{}{}", timestamp(&format_console_date()), "[SUCCESS] ".green(), message);
}

pub fn warning(message: impl std::fmt::Display) {
    println!("{}{}{}", timestamp(&format_console_date()), "[WARNING] ".yellow(), message);
}
