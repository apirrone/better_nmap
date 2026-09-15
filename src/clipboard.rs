//! Best-effort clipboard without native dependencies: an external tool when
//! one exists, otherwise the OSC 52 escape sequence (works over SSH in most
//! modern terminals and in tmux with `set-clipboard on`).

use std::io::Write;
use std::process::{Command, Stdio};

/// Copies `text`; returns a short description of how, or None on failure.
pub fn copy(text: &str) -> Option<&'static str> {
    let tools: &[(&str, &[&str])] = &[
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
        ("pbcopy", &[]),
    ];
    for (tool, args) in tools {
        let Ok(mut child) = Command::new(tool)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        if child.wait().map(|s| s.success()).unwrap_or(false) {
            return Some(tool);
        }
    }
    osc52(text).then_some("osc52")
}

fn osc52(text: &str) -> bool {
    let mut err = std::io::stderr();
    let seq = format!("\x1b]52;c;{}\x07", base64(text.as_bytes()));
    err.write_all(seq.as_bytes()).and_then(|_| err.flush()).is_ok()
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_reference() {
        assert_eq!(super::base64(b"192.168.10.162"), "MTkyLjE2OC4xMC4xNjI=");
        assert_eq!(super::base64(b"ab"), "YWI=");
        assert_eq!(super::base64(b"abc"), "YWJj");
    }
}
