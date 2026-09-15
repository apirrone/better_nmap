mod model;
mod net;
mod oui;
mod resolve;
mod scan;
mod ui;

use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::process::exit;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use model::{Event, Model};

const USAGE: &str = "\
bnmap - find devices on your network, fast

USAGE
    bnmap [OPTIONS] [QUERY]

Without options, opens the interactive TUI (rendered on stderr).
Enter prints the selected IP on stdout, so `ssh (bnmap)` / `ssh $(bnmap)` works.

OPTIONS
    -l, --list         Non-interactive: print a table of hosts and exit
    -1, --one QUERY    Print only the IP of the best match for QUERY
    -j, --json         Non-interactive: print hosts as JSON
    -i, --iface NAME   Network interface (default: the one with the default route)
    -r, --range CIDR   Range to sweep (default: the interface's subnet, max /23)
    -w, --wait SECS    Extra time to wait for slow DNS answers in batch mode (default 1)
    -h, --help         Show this help
    -V, --version      Show version

KEYS (TUI)
    type      fuzzy-filter on ip / hostname / vendor / mac
    ↑ ↓       move            enter     print selected ip and quit
    ctrl-r    rescan          esc       quit without output
";

struct Args {
    iface: Option<String>,
    range: Option<(Ipv4Addr, Ipv4Addr)>,
    list: bool,
    one: bool,
    json: bool,
    wait: f64,
    query: String,
}

fn parse_args() -> Args {
    let mut a = Args {
        iface: None,
        range: None,
        list: false,
        one: false,
        json: false,
        wait: 1.0,
        query: String::new(),
    };
    let mut it = std::env::args().skip(1);
    let mut words = Vec::new();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                exit(0);
            }
            "-V" | "--version" => {
                println!("bnmap {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            "-l" | "--list" => a.list = true,
            "-1" | "--one" => a.one = true,
            "-j" | "--json" => a.json = true,
            "-i" | "--iface" => a.iface = Some(it.next().unwrap_or_else(|| die("--iface needs a value"))),
            "-r" | "--range" => {
                let v = it.next().unwrap_or_else(|| die("--range needs a value"));
                a.range = Some(net::parse_cidr(&v).unwrap_or_else(|e| die(&format!("--range: {e}"))));
            }
            "-w" | "--wait" => {
                let v = it.next().unwrap_or_else(|| die("--wait needs a value"));
                a.wait = v.parse().unwrap_or_else(|_| die("--wait: expected seconds"));
            }
            s if s.starts_with('-') && s.len() > 1 => die(&format!("unknown option '{s}' (try --help)")),
            _ => words.push(arg),
        }
    }
    a.query = words.join(" ");
    if a.one && a.query.is_empty() {
        die("--one needs a QUERY");
    }
    a
}

fn die(msg: &str) -> ! {
    eprintln!("bnmap: {msg}");
    exit(2)
}

fn main() {
    let args = parse_args();
    let iface = net::pick_iface(args.iface.as_deref()).unwrap_or_else(|e| die(&e));

    if !(args.list || args.one || args.json) {
        match ui::run(iface, args.range, args.query) {
            Ok(Some(ip)) => println!("{ip}"),
            Ok(None) => exit(1),
            Err(e) => die(&e.to_string()),
        }
        return;
    }

    // Batch mode: run the scan to completion, then give DNS a little slack.
    let (tx, rx) = mpsc::channel();
    let mut model = Model::new(&iface);
    scan::start(iface, scan::Options { range: args.range }, tx);
    while let Ok(ev) = rx.recv() {
        let done = matches!(ev, Event::Done);
        model.apply(ev);
        if done {
            break;
        }
    }
    let deadline = Instant::now() + Duration::from_secs_f64(args.wait);
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(ev) => model.apply(ev),
            Err(_) => break,
        }
    }

    if args.one {
        match model.best(&args.query) {
            Some(h) => println!("{}", h.ip),
            None => {
                eprintln!("bnmap: no host matches '{}'", args.query);
                exit(1);
            }
        }
        return;
    }

    let rows = model.filtered(&args.query);
    if args.json {
        print_json(&model, &rows);
    } else {
        print_table(&model, &rows);
    }
}

/// Print a line to stdout; a closed pipe (`bnmap -l | head`) ends quietly.
fn out(line: String) {
    if writeln!(io::stdout().lock(), "{line}").is_err() {
        exit(0);
    }
}

fn print_table(model: &Model, rows: &[usize]) {
    let name_w = rows
        .iter()
        .map(|&i| {
            let h = &model.hosts[i];
            h.name().map_or(1, str::len) + if h.is_self { " (this machine)".len() } else { 0 }
        })
        .max()
        .unwrap_or(8)
        .max(8);
    out(format!(
        "{:<16} {:<name_w$}  {:<17}  {}",
        "IP", "HOSTNAME", "MAC", "VENDOR"
    ));
    for &i in rows {
        let h = &model.hosts[i];
        let mut name = h.name().unwrap_or("-").to_string();
        if h.is_self {
            name.push_str(" (this machine)");
        }
        out(format!("{:<16} {:<name_w$}  {:<17}  {}", h.ip, name, h.mac, h.vendor));
    }
}

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if c.is_control() => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn print_json(model: &Model, rows: &[usize]) {
    out("[".into());
    for (n, &i) in rows.iter().enumerate() {
        let h = &model.hosts[i];
        let names: Vec<String> = h
            .names
            .iter()
            .map(|(s, n)| format!("{{\"source\":{},\"name\":{}}}", json_str(s.label()), json_str(n)))
            .collect();
        out(format!(
            "  {{\"ip\":{},\"mac\":{},\"vendor\":{},\"reachable\":{},\"self\":{},\"hostname\":{},\"names\":[{}]}}{}",
            json_str(&h.ip.to_string()),
            json_str(&h.mac),
            json_str(&h.vendor),
            h.reachable,
            h.is_self,
            h.name().map_or("null".to_string(), json_str),
            names.join(","),
            if n + 1 < rows.len() { "," } else { "" }
        ));
    }
    out("]".into());
}
