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

    // Phase 1: ARP sweep via kernel, three rounds so slow devices get a chance.
    let _ = tx.send(Event::Phase("arp"));
    let mut alive: Vec<Ipv4Addr> = vec![iface.ip];
    let mut known = std::collections::HashMap::<Ipv4Addr, bool>::new();
    for round in 0..3 {
        net::poke(&hosts);
        thread::sleep(Duration::from_millis(if round == 0 { 400 } else { 300 }));
        for n in net::neighbours(&iface.name) {
            if !hosts.contains(&n.ip) {
                continue;
            }
            let prev = known.insert(n.ip, n.reachable);
            if prev != Some(n.reachable) || prev.is_none() {
                if prev.is_none() {
                    alive.push(n.ip);
                }
                let _ = tx.send(Event::Host {
                    ip: n.ip,
                    mac: n.mac,
                    reachable: n.reachable,
                    is_self: false,
                });
            }
        }
    }

    // Phase 2: names, all resolvers in parallel.
    let _ = tx.send(Event::Phase("names"));
    let alive = Arc::new(alive);
    let budget = Duration::from_millis(1500);

    let t_mdns = {
        let (tx, alive, ip) = (tx.clone(), alive.clone(), iface.ip);
        thread::spawn(move || {
            resolve::mdns(ip, &alive, budget, |ip, name| {
                let _ = tx.send(Event::Name {
                    ip,
                    source: Source::Mdns,
                    name,
                });
            })
        })
    };
    let t_nbt = {
        let (tx, alive) = (tx.clone(), alive.clone());
        thread::spawn(move || {
            resolve::netbios(&alive, budget, |ip, name| {
                let _ = tx.send(Event::Name {
                    ip,
                    source: Source::NetBios,
                    name,
                });
            })
        })
    };
    // System DNS can block for seconds per host; run on a pool, don't wait for it.
    let pool = 16usize;
    for k in 0..pool {
        let (tx, alive) = (tx.clone(), alive.clone());
        thread::spawn(move || {
            for ip in alive.iter().skip(k).step_by(pool) {
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

    let _ = t_mdns.join();
    let _ = t_nbt.join();
    let _ = tx.send(Event::Done);
}
