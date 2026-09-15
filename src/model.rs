//! Shared state between the scanner and the two front-ends (TUI, batch).

use std::net::Ipv4Addr;

use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;

use crate::net::Iface;
use crate::resolve::Source;

#[derive(Debug)]
pub enum Event {
    Host {
        ip: Ipv4Addr,
        mac: String,
        reachable: bool,
        is_self: bool,
    },
    Name {
        ip: Ipv4Addr,
        source: Source,
        name: String,
    },
    Phase(&'static str),
    /// ARP + mDNS + NetBIOS finished; slow DNS answers may still trickle in.
    Done,
}

#[derive(Clone, Debug)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub vendor: String,
    pub reachable: bool,
    pub is_self: bool,
    pub names: Vec<(Source, String)>,
}

impl Host {
    /// Best display name: mDNS, then DNS, then NetBIOS.
    pub fn name(&self) -> Option<&str> {
        self.names.iter().min_by_key(|(s, _)| *s).map(|(_, n)| n.as_str())
    }
    pub fn haystack(&self) -> String {
        let mut s = self.ip.to_string();
        for (_, n) in &self.names {
            s.push(' ');
            s.push_str(n);
        }
        s.push(' ');
        s.push_str(&self.vendor);
        s.push(' ');
        s.push_str(&self.mac);
        s
    }
}

pub struct Model {
    pub hosts: Vec<Host>,
    pub iface: String,
    pub cidr: String,
    pub phase: &'static str,
    pub done: bool,
    matcher: SkimMatcherV2,
}

impl Model {
    pub fn new(iface: &Iface) -> Self {
        Model {
            hosts: Vec::new(),
            iface: iface.name.clone(),
            cidr: iface.cidr(),
            phase: "starting",
            done: false,
            matcher: SkimMatcherV2::default().ignore_case(),
        }
    }

    pub fn reset(&mut self) {
        self.hosts.clear();
        self.done = false;
        self.phase = "starting";
    }

    pub fn apply(&mut self, ev: Event) {
        match ev {
            Event::Host {
                ip,
                mac,
                reachable,
                is_self,
            } => match self.hosts.binary_search_by_key(&ip, |h| h.ip) {
                Ok(i) => {
                    let h = &mut self.hosts[i];
                    h.reachable |= reachable;
                    if h.mac != mac {
                        h.mac = mac;
                        h.vendor = crate::oui::vendor(&h.mac);
                    }
                }
                Err(i) => {
                    let vendor = crate::oui::vendor(&mac);
                    self.hosts.insert(
                        i,
                        Host {
                            ip,
                            mac,
                            vendor,
                            reachable,
                            is_self,
                            names: Vec::new(),
                        },
                    );
                }
            },
            Event::Name { ip, source, name } => {
                let name = name.trim_end_matches('.').to_string();
                if let Ok(i) = self.hosts.binary_search_by_key(&ip, |h| h.ip) {
                    let h = &mut self.hosts[i];
                    if !h.names.iter().any(|(_, n)| n.eq_ignore_ascii_case(&name)) {
                        h.names.push((source, name));
                    }
                }
            }
            Event::Phase(p) => self.phase = p,
            Event::Done => {
                self.done = true;
                self.phase = "done";
            }
        }
    }

    /// Indices into `hosts` matching `query`, best first (IP order when empty).
    pub fn filtered(&self, query: &str) -> Vec<usize> {
        let q = query.trim();
        if q.is_empty() {
            return (0..self.hosts.len()).collect();
        }
        let mut scored: Vec<(i64, usize)> = self
            .hosts
            .iter()
            .enumerate()
            .filter_map(|(i, h)| self.matcher.fuzzy_match(&h.haystack(), q).map(|s| (s, i)))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.into_iter().map(|(_, i)| i).collect()
    }

    /// Single best match for scripting: exact IP / name first, then fuzzy.
    pub fn best(&self, query: &str) -> Option<&Host> {
        let q = query.trim().to_lowercase();
        let exact = self.hosts.iter().find(|h| {
            h.ip.to_string() == q
                || h.names.iter().any(|(_, n)| {
                    let n = n.to_lowercase();
                    n == q || n.strip_suffix(".local") == Some(q.as_str())
                })
        });
        exact.or_else(|| self.filtered(&q).first().map(|&i| &self.hosts[i]))
    }
}
