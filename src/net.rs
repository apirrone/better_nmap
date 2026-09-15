//! Interface detection and root-free host discovery.
//!
//! Discovery trick: sending any UDP datagram to an address on the local
//! subnet forces the kernel to ARP-resolve it. After a short wait, the
//! kernel neighbour table holds every host that answered, with its MAC.
//! No raw sockets, no root.

use std::net::{Ipv4Addr, UdpSocket};
use std::process::Command;

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub mac: Option<String>,
}

impl Iface {
    pub fn prefix_len(&self) -> u32 {
        u32::from(self.mask).count_ones()
    }
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip) & u32::from(self.mask))
    }
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network(), self.prefix_len())
    }
}

/// Interface carrying the default route, from /proc/net/route.
fn default_route_iface() -> Option<String> {
    let s = std::fs::read_to_string("/proc/net/route").ok()?;
    s.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 2 && f[1] == "00000000").then(|| f[0].to_string())
    })
}

pub fn pick_iface(want: Option<&str>) -> Result<Iface, String> {
    let all = if_addrs::get_if_addrs().map_err(|e| e.to_string())?;
    let mut cands: Vec<Iface> = all
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => Some(Iface {
                name: i.name,
                ip: v4.ip,
                mask: v4.netmask,
                mac: None,
            }),
            _ => None,
        })
        .collect();
    if cands.is_empty() {
        return Err("no IPv4 network interface found".into());
    }
    let idx = match want {
        Some(w) => cands
            .iter()
            .position(|c| c.name == w)
            .ok_or_else(|| format!("interface '{w}' has no IPv4 address"))?,
        None => default_route_iface()
            .and_then(|d| cands.iter().position(|c| c.name == d))
            .unwrap_or(0),
    };
    let mut iface = cands.swap_remove(idx);
    iface.mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface.name))
        .ok()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && s != "00:00:00:00:00:00");
    Ok(iface)
}

/// Parse "a.b.c.d/nn" into (network, mask).
pub fn parse_cidr(s: &str) -> Result<(Ipv4Addr, Ipv4Addr), String> {
    let (ip, len) = s.split_once('/').ok_or("expected a.b.c.d/nn")?;
    let ip: Ipv4Addr = ip.parse().map_err(|_| "bad address")?;
    let len: u32 = len.parse().map_err(|_| "bad prefix length")?;
    if len > 32 {
        return Err("prefix length > 32".into());
    }
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Ok((Ipv4Addr::from(u32::from(ip) & mask), Ipv4Addr::from(mask)))
}

/// Largest range we sweep; wider subnets are clipped around our own IP so we
/// never overflow the kernel neighbour table (gc_thresh3 defaults to 1024).
pub const MAX_PREFIX_HOSTS: u32 = 23;

/// All host addresses to probe, excluding network, broadcast and ourselves.
pub fn hosts(iface: &Iface) -> (Vec<Ipv4Addr>, bool) {
    let ip = u32::from(iface.ip);
    let mut mask = u32::from(iface.mask);
    let clip_mask = u32::MAX << (32 - MAX_PREFIX_HOSTS);
    let clipped = mask.count_ones() < MAX_PREFIX_HOSTS;
    if clipped {
        mask = clip_mask;
    }
    let net = ip & mask;
    let bcast = net | !mask;
    let v = (net + 1..bcast).filter(|&h| h != ip).map(Ipv4Addr::from).collect();
    (v, clipped)
}

/// Trigger kernel ARP resolution for every host (see module docs).
///
/// Each datagram to an unresolved neighbour stays charged to the socket's
/// send buffer until ARP succeeds or gives up, so a plain blocking socket
/// stalls after ~100 hosts. We go non-blocking and swap in a fresh socket
/// whenever the buffer is full.
pub fn poke(hosts: &[Ipv4Addr]) {
    let fresh = || {
        UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.set_nonblocking(true).map(|_| s))
            .ok()
    };
    let Some(mut sock) = fresh() else { return };
    for h in hosts {
        // Port 9 is "discard"; nobody listens, nobody cares.
        if let Err(e) = sock.send_to(&[0u8], (*h, 9)) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                match fresh() {
                    Some(s) => sock = s,
                    None => return,
                }
                let _ = sock.send_to(&[0u8], (*h, 9));
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Neigh {
    pub ip: Ipv4Addr,
    pub mac: String,
    /// true only when the kernel has recently confirmed the host answered.
    pub reachable: bool,
}

/// Read the IPv4 neighbour table for one interface.
pub fn neighbours(iface: &str) -> Vec<Neigh> {
    if let Ok(out) = Command::new("ip").args(["-4", "neigh", "show", "dev", iface]).output() {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    let ip: Ipv4Addr = f.first()?.parse().ok()?;
                    let pos = f.iter().position(|&t| t == "lladdr")?;
                    let mac = f.get(pos + 1)?.to_lowercase();
                    let state = f.last().copied().unwrap_or("");
                    let reachable = matches!(state, "REACHABLE" | "PERMANENT" | "NOARP");
                    Some(Neigh { ip, mac, reachable })
                })
                .collect();
        }
    }
    // Fallback: /proc/net/arp has no state, only "complete" (0x2) flag.
    std::fs::read_to_string("/proc/net/arp")
        .map(|s| {
            s.lines()
                .skip(1)
                .filter_map(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    if f.len() < 6 || f[5] != iface || f[2] != "0x2" {
                        return None;
                    }
                    Some(Neigh {
                        ip: f[0].parse().ok()?,
                        mac: f[3].to_lowercase(),
                        reachable: true,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parsing() {
        let (n, m) = parse_cidr("192.168.10.77/24").unwrap();
        assert_eq!(n, Ipv4Addr::new(192, 168, 10, 0));
        assert_eq!(m, Ipv4Addr::new(255, 255, 255, 0));
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("nope").is_err());
    }

    #[test]
    fn hosts_are_clipped_on_wide_subnets() {
        let iface = Iface {
            name: "x".into(),
            ip: Ipv4Addr::new(10, 1, 2, 3),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            mac: None,
        };
        let (h, clipped) = hosts(&iface);
        assert_eq!(h.len(), 253);
        assert!(!clipped);
        assert!(!h.contains(&iface.ip));
        let wide = Iface {
            mask: Ipv4Addr::new(255, 255, 0, 0),
            ..iface
        };
        let (h, clipped) = hosts(&wide);
        assert_eq!(h.len(), 509);
        assert!(clipped);
    }
}
