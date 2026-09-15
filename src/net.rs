//! Interface detection and root-free host discovery.
//!
//! Discovery trick: sending any UDP datagram to an address on the local
//! subnet forces the kernel to ARP-resolve it. After a short wait, the
//! kernel neighbour table holds every host that answered, with its MAC.
//! No raw sockets, no root.
//!
//! The sweep itself is plain UDP and portable. Reading the result back is
//! not: Linux exposes the neighbour table through `ip neigh` and /proc,
//! macOS through BSD `arp -an`. Each platform gets its own reader below;
//! the parsing is split into pure functions so every one of them stays
//! under test wherever the suite runs.

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

/// Lowercase a MAC and zero-pad its octets.
///
/// BSD `arp` prints octets unpadded ("22:2a:68:84:d:23"), which misaligns
/// the table and, when a leading octet is short, shifts the six hex digits
/// the OUI lookup slices off the front.
fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6
        || !parts
            .iter()
            .all(|p| (1..=2).contains(&p.len()) && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(
        parts
            .iter()
            .map(|p| format!("{:0>2}", p.to_lowercase()))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Interface carrying the default route, from /proc/net/route.
// Kept compiled on every platform so its unit test runs wherever the suite does.
#[allow(dead_code)]
fn parse_proc_route(s: &str) -> Option<String> {
    s.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 2 && f[1] == "00000000").then(|| f[0].to_string())
    })
}

/// Interface carrying the default route, from `route -n get default`.
// Kept compiled on every platform so its unit test runs wherever the suite does.
#[allow(dead_code)]
fn parse_route_get(s: &str) -> Option<String> {
    s.lines()
        .find_map(|l| l.split_once("interface:").map(|(_, v)| v.trim().to_string()))
        .filter(|v| !v.is_empty())
}

#[cfg(not(target_os = "macos"))]
fn default_route_iface() -> Option<String> {
    parse_proc_route(&std::fs::read_to_string("/proc/net/route").ok()?)
}

#[cfg(target_os = "macos")]
fn default_route_iface() -> Option<String> {
    let out = Command::new("route").args(["-n", "get", "default"]).output().ok()?;
    out.status
        .success()
        .then(|| parse_route_get(&String::from_utf8_lossy(&out.stdout)))?
}

/// Our own MAC on `iface`, from the `ether` line of `ifconfig`.
// Kept compiled on every platform so its unit test runs wherever the suite does.
#[allow(dead_code)]
fn parse_ifconfig_ether(s: &str) -> Option<String> {
    s.lines().find_map(|l| {
        let t = l.trim();
        t.strip_prefix("ether ").and_then(|m| normalize_mac(m.trim()))
    })
}

#[cfg(not(target_os = "macos"))]
fn iface_mac(name: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .ok()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && s != "00:00:00:00:00:00")
}

#[cfg(target_os = "macos")]
fn iface_mac(name: &str) -> Option<String> {
    let out = Command::new("ifconfig").arg(name).output().ok()?;
    out.status
        .success()
        .then(|| parse_ifconfig_ether(&String::from_utf8_lossy(&out.stdout)))?
        .filter(|s| s != "00:00:00:00:00:00")
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
    iface.mac = iface_mac(&iface.name);
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

/// Parse `ip -4 neigh show dev IFACE`.
// Kept compiled on every platform so its unit test runs wherever the suite does.
#[allow(dead_code)]
fn parse_ip_neigh(s: &str) -> Vec<Neigh> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let ip: Ipv4Addr = f.first()?.parse().ok()?;
            let pos = f.iter().position(|&t| t == "lladdr")?;
            let mac = normalize_mac(f.get(pos + 1)?)?;
            let state = f.last().copied().unwrap_or("");
            let reachable = matches!(state, "REACHABLE" | "PERMANENT" | "NOARP");
            Some(Neigh { ip, mac, reachable })
        })
        .collect()
}

/// Parse /proc/net/arp, which has no state, only the "complete" (0x2) flag.
// Kept compiled on every platform so its unit test runs wherever the suite does.
#[allow(dead_code)]
fn parse_proc_arp(s: &str, iface: &str) -> Vec<Neigh> {
    s.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 6 || f[5] != iface || f[2] != "0x2" {
                return None;
            }
            Some(Neigh {
                ip: f[0].parse().ok()?,
                mac: normalize_mac(f[3])?,
                reachable: true,
            })
        })
        .collect()
}

/// Parse BSD `arp -an`, whose lines look like
/// `? (192.168.1.4) at 10:7c:61:df:7a:28 on en0 ifscope [ethernet]`.
///
/// Unresolved slots read `at (incomplete)` and are dropped. Like
/// /proc/net/arp this carries no reachability state, so a resolved entry
/// counts as reachable — same convention as the Linux fallback.
// Kept compiled on every platform so its unit test runs wherever the suite does.
#[allow(dead_code)]
fn parse_bsd_arp(s: &str, iface: &str) -> Vec<Neigh> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // The address is the sole parenthesised field before "at".
            let at = f.iter().position(|&t| t == "at")?;
            let ip: Ipv4Addr = f[..at].iter().find_map(|t| t.trim_matches(['(', ')']).parse().ok())?;
            let mac = normalize_mac(f.get(at + 1)?)?;
            // `arp -i` already filters, but a plain `arp -an` does not.
            let on = f.iter().position(|&t| t == "on")?;
            (*f.get(on + 1)? == iface).then_some(Neigh {
                ip,
                mac,
                reachable: true,
            })
        })
        .collect()
}

/// Read the IPv4 neighbour table for one interface.
#[cfg(not(target_os = "macos"))]
pub fn neighbours(iface: &str) -> Vec<Neigh> {
    if let Ok(out) = Command::new("ip").args(["-4", "neigh", "show", "dev", iface]).output() {
        if out.status.success() {
            return parse_ip_neigh(&String::from_utf8_lossy(&out.stdout));
        }
    }
    std::fs::read_to_string("/proc/net/arp")
        .map(|s| parse_proc_arp(&s, iface))
        .unwrap_or_default()
}

/// Read the IPv4 neighbour table for one interface.
#[cfg(target_os = "macos")]
pub fn neighbours(iface: &str) -> Vec<Neigh> {
    let Ok(out) = Command::new("arp").args(["-a", "-n", "-i", iface]).output() else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    parse_bsd_arp(&String::from_utf8_lossy(&out.stdout), iface)
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

    #[test]
    fn macs_are_padded_and_lowercased() {
        assert_eq!(normalize_mac("22:2A:68:84:D:23").unwrap(), "22:2a:68:84:0d:23");
        assert_eq!(normalize_mac("1:0:5e:0:0:fb").unwrap(), "01:00:5e:00:00:fb");
        assert!(normalize_mac("(incomplete)").is_none());
        assert!(normalize_mac("10:7c:61:df:7a").is_none());
        assert!(normalize_mac("zz:7c:61:df:7a:28").is_none());
    }

    #[test]
    fn default_route_from_both_platforms() {
        let proc_route = "Iface\tDestination\tGateway\tFlags\nwlp3s0\t00000000\t0102A8C0\t0003\n\
                          wlp3s0\t0002A8C0\t00000000\t0001\n";
        assert_eq!(parse_proc_route(proc_route).unwrap(), "wlp3s0");
        let route_get = "   route to: default\ndestination: default\n       gateway: 192.168.50.1\n  \
                         interface: en0\n     flags: <UP,GATEWAY,DONE,STATIC>\n";
        assert_eq!(parse_route_get(route_get).unwrap(), "en0");
        assert!(parse_route_get("   route to: default\n").is_none());
    }

    #[test]
    fn own_mac_from_ifconfig() {
        let out = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                   \toptions=6460<TSO4,TSO6,CHANNEL_IO>\n\
                   \tether 22:2a:68:84:0d:23\n\
                   \tinet 192.168.50.8 netmask 0xffffff00 broadcast 192.168.50.255\n";
        assert_eq!(parse_ifconfig_ether(out).unwrap(), "22:2a:68:84:0d:23");
        assert!(parse_ifconfig_ether("lo0: flags=8049<UP,LOOPBACK>\n").is_none());
    }

    #[test]
    fn bsd_arp_table() {
        let out = "? (169.254.169.254) at (incomplete) on en0 [ethernet]\n\
                   ? (192.168.50.1) at 10:7c:61:df:7a:28 on en0 ifscope [ethernet]\n\
                   ? (192.168.50.2) at (incomplete) on en0 ifscope [ethernet]\n\
                   ? (192.168.50.8) at 22:2a:68:84:d:23 on en0 ifscope permanent [ethernet]\n\
                   ? (192.168.50.99) at 50:37:cd:16:9e:6a on en1 ifscope [ethernet]\n\
                   ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n";
        let n = parse_bsd_arp(out, "en0");
        // Incomplete slots dropped, the en1 entry dropped, octets padded.
        let got: Vec<(String, String)> = n.iter().map(|x| (x.ip.to_string(), x.mac.clone())).collect();
        assert_eq!(
            got,
            vec![
                ("192.168.50.1".to_string(), "10:7c:61:df:7a:28".to_string()),
                ("192.168.50.8".to_string(), "22:2a:68:84:0d:23".to_string()),
                ("224.0.0.251".to_string(), "01:00:5e:00:00:fb".to_string()),
            ]
        );
        assert!(n.iter().all(|x| x.reachable));
    }

    #[test]
    fn linux_neighbour_tables() {
        let neigh = "192.168.50.1 lladdr 10:7c:61:df:7a:28 REACHABLE\n\
                     192.168.50.2 lladdr 22:2a:68:84:0d:23 STALE\n\
                     192.168.50.3  FAILED\n";
        let n = parse_ip_neigh(neigh);
        assert_eq!(n.len(), 2);
        assert!(n[0].reachable);
        assert!(!n[1].reachable);
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                   192.168.50.1     0x1         0x2         10:7c:61:df:7a:28     *        wlp3s0\n\
                   192.168.50.2     0x1         0x0         00:00:00:00:00:00     *        wlp3s0\n\
                   192.168.50.3     0x1         0x2         22:2a:68:84:0d:23     *        eth0\n";
        let n = parse_proc_arp(arp, "wlp3s0");
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].mac, "10:7c:61:df:7a:28");
    }
}
