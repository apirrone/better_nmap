//! ratatui front-end. Draws on stderr so stdout carries only the chosen IP.

use std::io;
use std::net::Ipv4Addr;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};

use crate::model::{Event, Model};
use crate::net::Iface;
use crate::scan;

const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn run(iface: Iface, range: Option<(Ipv4Addr, Ipv4Addr)>, query: String) -> io::Result<Option<Ipv4Addr>> {
    let start_scan = || {
        let (tx, rx) = mpsc::channel();
        scan::start(iface.clone(), scan::Options { range }, tx);
        rx
    };
    let mut model = Model::new(&iface);
    let rx = start_scan();

    enable_raw_mode()?;
    io::stderr().execute(EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stderr()))?;
    let res = event_loop(&mut term, &mut model, rx, start_scan, query);
    disable_raw_mode()?;
    io::stderr().execute(LeaveAlternateScreen)?;
    res
}

fn event_loop(
    term: &mut Terminal<CrosstermBackend<io::Stderr>>,
    model: &mut Model,
    mut rx: Receiver<Event>,
    rescan: impl Fn() -> Receiver<Event>,
    mut query: String,
) -> io::Result<Option<Ipv4Addr>> {
    let mut selected = 0usize;
    let mut table_state = TableState::default();
    let started = Instant::now();

    loop {
        while let Ok(ev) = rx.try_recv() {
            model.apply(ev);
        }

        let rows = model.filtered(&query);
        if rows.is_empty() {
            selected = 0;
        } else if selected >= rows.len() {
            selected = rows.len() - 1;
        }
        table_state.select(if rows.is_empty() { None } else { Some(selected) });

        let tick = (started.elapsed().as_millis() / 80) as usize % SPINNER.len();
        term.draw(|f| draw(f, model, &query, &rows, &mut table_state, tick))?;

        if !event::poll(Duration::from_millis(50))? {
            continue;
        }
        let CEvent::Key(k) = event::read()? else { continue };
        if k.kind != KeyEventKind::Press {
            continue;
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match (k.code, ctrl) {
            (KeyCode::Esc, _) | (KeyCode::Char('c'), true) | (KeyCode::Char('g'), true) => return Ok(None),
            (KeyCode::Enter, _) => return Ok(rows.get(selected).map(|&i| model.hosts[i].ip)),
            (KeyCode::Up, _) | (KeyCode::Char('p'), true) => selected = selected.saturating_sub(1),
            (KeyCode::Down, _) | (KeyCode::Char('n'), true) => selected += 1,
            (KeyCode::PageUp, _) => selected = selected.saturating_sub(10),
            (KeyCode::PageDown, _) => selected += 10,
            (KeyCode::Home, _) => selected = 0,
            (KeyCode::End, _) => selected = usize::MAX / 2,
            (KeyCode::Char('u'), true) => query.clear(),
            (KeyCode::Char('w'), true) => {
                let trimmed = query.trim_end().len();
                query.truncate(trimmed);
                while query.pop().is_some_and(|c| !c.is_whitespace()) {}
            }
            (KeyCode::Char('r'), true) => {
                model.reset();
                rx = rescan();
            }
            (KeyCode::Backspace, _) => {
                query.pop();
            }
            (KeyCode::Char(c), false) => query.push(c),
            _ => {}
        }
    }
}

fn draw(f: &mut Frame, model: &Model, query: &str, rows: &[usize], state: &mut TableState, tick: usize) {
    let [header, search, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(f.area());

    let reachable = model.hosts.iter().filter(|h| h.reachable).count();
    let status = if model.done {
        Span::styled(format!("{} hosts", model.hosts.len()), Style::new().green())
    } else {
        Span::styled(
            format!(
                "{} scanning {}…  {} hosts",
                SPINNER[tick],
                model.phase,
                model.hosts.len()
            ),
            Style::new().yellow(),
        )
    };
    f.render_widget(
        Line::from(vec![
            Span::styled(" bnmap ", Style::new().bold().reversed()),
            Span::raw(format!(" {}  {}   ", model.iface, model.cidr)),
            status,
            Span::styled(format!("  ({reachable} confirmed)"), Style::new().dim()),
        ]),
        header,
    );

    f.render_widget(
        Line::from(vec![
            Span::styled(" > ", Style::new().cyan().bold()),
            Span::raw(query),
            Span::styled("▏", Style::new().dim()),
            Span::styled(
                if query.is_empty() {
                    "type to fuzzy-search ip / hostname / vendor"
                } else {
                    ""
                },
                Style::new().dim().italic(),
            ),
        ]),
        search,
    );

    let table_rows = rows.iter().map(|&i| {
        let h = &model.hosts[i];
        let dot = if h.reachable {
            Span::styled("●", Style::new().green())
        } else {
            Span::styled("○", Style::new().dark_gray())
        };
        let mut name = h.name().unwrap_or("").to_string();
        if h.is_self {
            name = if name.is_empty() {
                "(this machine)".into()
            } else {
                format!("{name} (this machine)")
            };
        }
        let extra = h.names.len().saturating_sub(1);
        let name_cell = if extra > 0 {
            Line::from(vec![
                Span::raw(name),
                Span::styled(format!(" +{extra}"), Style::new().dim()),
            ])
        } else {
            Line::from(name)
        };
        Row::new(vec![
            Cell::from(Line::from(vec![
                dot,
                Span::raw(" "),
                Span::styled(h.ip.to_string(), Style::new().cyan()),
            ])),
            Cell::from(name_cell).style(Style::new().bold()),
            Cell::from(h.mac.clone()).style(Style::new().dim()),
            Cell::from(h.vendor.clone()).style(Style::new().yellow()),
        ])
    });
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(18),
            Constraint::Min(20),
            Constraint::Length(18),
            Constraint::Length(30),
        ],
    )
    .header(Row::new(vec!["  IP", "HOSTNAME", "MAC", "VENDOR"]).style(Style::new().dim().underlined()))
    .row_highlight_style(Style::new().reversed())
    .block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::new().dark_gray()),
    );
    f.render_stateful_widget(table, body, state);

    let empty = model.done && rows.is_empty();
    let hint = if empty && !query.is_empty() {
        Line::from(Span::styled(" no match", Style::new().red()))
    } else {
        Line::from(vec![
            key("↑↓"),
            Span::raw(" move  "),
            key("enter"),
            Span::raw(" print ip  "),
            key("ctrl-r"),
            Span::raw(" rescan  "),
            key("esc"),
            Span::raw(" quit"),
        ])
    };
    f.render_widget(Paragraph::new(hint).style(Style::new().dim()), footer);
}

fn key(s: &str) -> Span<'static> {
    Span::styled(s.to_string(), Style::new().bold().not_dim())
}
