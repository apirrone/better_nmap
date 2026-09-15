//! Scan orchestration: ARP sweep, then parallel name resolution.
//! Streams `Event`s to the caller; returns immediately.

use std::net::Ipv4Addr;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::model::Event;
use crate::net::{self, Iface};
use crate::resolve::{self, Source};

pub struct Options {
    pub range: Option<(Ipv4Addr, Ipv4Addr)>,
}

pub fn start(iface: Iface, opts: Options, tx: Sender<Event>) {
    thread::spawn(move || run(iface, opts, tx));
}

fn run(iface: Iface, opts: Options, tx: Sender<Event>) {
    let hosts: Vec<Ipv4Addr> = match opts.range {
        Some((net, mask)) => {
            let (n, m) = (u32::from(net), u32::from(mask));
            (n + 1..(n | !m))
                .filter(|&h| h != u32::from(iface.ip))
                .map(Ipv4Addr::from)
                .collect()
        }
        None => net::hosts(&iface).0,
    };

    if let Some(mac) = &iface.mac {
        let _ = tx.send(Event::Host {
            ip: iface.ip,
            mac: mac.clone(),
            reachable: true,
            is_self: true,
        });
    }

    // Phase 1: ARP sweep via kernel. Slow or sleepy devices (Wi-Fi power
    // save, cellular modules) can take seconds to answer, so we keep polling
    // the neighbour table during the whole scan, not just here.
    let _ = tx.send(Event::Phase("arp"));
    let mut known = std::collections::HashMap::<Ipv4Addr, bool>::new();
    let collect = |known: &mut std::collections::HashMap<Ipv4Addr, bool>, new: &mut Vec<Ipv4Addr>| {
        for n in net::neighbours(&iface.name) {
            if !hosts.contains(&n.ip) {
                continue;
            }
            let prev = known.insert(n.ip, n.reachable);
            if prev.is_none() {
                new.push(n.ip);
            }
            if prev != Some(n.reachable) {
                let _ = tx.send(Event::Host {
                    ip: n.ip,
                    mac: n.mac,
                    reachable: n.reachable,
                    is_self: false,
                });
            }
        }
    };
    let mut alive: Vec<Ipv4Addr> = vec![iface.ip];
    for round in 0..3 {
        net::poke(&hosts);
        thread::sleep(Duration::from_millis(if round == 0 { 400 } else { 300 }));
        collect(&mut known, &mut alive);
    }

    // Phase 2: names, all resolvers in parallel, while ARP keeps being polled.
    let _ = tx.send(Event::Phase("names"));
    let budget = Duration::from_millis(1500);
    let (t_mdns, t_nbt) = resolve_all(&iface, &tx, alive, budget);

    let mut late = Vec::new();
    while !(t_mdns.is_finished() && t_nbt.is_finished()) {
        thread::sleep(Duration::from_millis(250));
        net::poke(&hosts);
        collect(&mut known, &mut late);
    }
    let _ = t_mdns.join();
    let _ = t_nbt.join();

    // Late arrivals get a shorter resolution pass of their own.
    if !late.is_empty() {
        let (a, b) = resolve_all(&iface, &tx, late, Duration::from_millis(800));
        let _ = a.join();
        let _ = b.join();
    }
    let _ = tx.send(Event::Done);
}

/// Spawn mDNS, NetBIOS and DNS lookups for `targets`. Returns the mDNS and
/// NetBIOS handles; DNS runs on a detached pool since it can block for long.
fn resolve_all(
    iface: &Iface,
    tx: &Sender<Event>,
    targets: Vec<Ipv4Addr>,
    budget: Duration,
) -> (thread::JoinHandle<()>, thread::JoinHandle<()>) {
    let targets = Arc::new(targets);
    let t_mdns = {
        let (tx, targets, ip) = (tx.clone(), targets.clone(), iface.ip);
        thread::spawn(move || {
            resolve::mdns(ip, &targets, budget, |ip, name| {
                let _ = tx.send(Event::Name {
                    ip,
                    source: Source::Mdns,
                    name,
                });
            })
        })
    };
    let t_nbt = {
        let (tx, targets) = (tx.clone(), targets.clone());
        thread::spawn(move || {
            resolve::netbios(&targets, budget, |ip, name| {
                let _ = tx.send(Event::Name {
                    ip,
                    source: Source::NetBios,
                    name,
                });
            })
        })
    };
    let pool = 16usize.min(targets.len().max(1));
    for k in 0..pool {
        let (tx, targets) = (tx.clone(), targets.clone());
        thread::spawn(move || {
            for ip in targets.iter().skip(k).step_by(pool) {
                if let Some(name) = resolve::dns(*ip) {
                    let _ = tx.send(Event::Name {
                        ip: *ip,
                        source: Source::Dns,
                        name,
                    });
                }
            }
        });
    }
    (t_mdns, t_nbt)
}
