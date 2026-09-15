//! Hostname resolution: mDNS, NetBIOS and system reverse DNS.
//! Each resolver takes the list of live hosts and a callback for results.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    Mdns,
    Dns,
    NetBios,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Mdns => "mdns",
            Source::Dns => "dns",
            Source::NetBios => "nbt",
        }
    }
}

// ---------------------------------------------------------------- DNS bits

fn u16be(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Decode a possibly-compressed name; returns (name, offset just after it).
fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *buf.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            pos = ptr;
            continue;
        }
        labels.push(String::from_utf8_lossy(buf.get(pos + 1..pos + 1 + len)?).into_owned());
        pos += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

fn ip_from_reverse(name: &str) -> Option<Ipv4Addr> {
    let rest = name.strip_suffix(".in-addr.arpa")?;
    let o: Vec<u8> = rest.split('.').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    (o.len() == 4).then(|| Ipv4Addr::new(o[3], o[2], o[1], o[0]))
}

/// One-question PTR query. `unicast` sets the mDNS QU bit.
fn ptr_query(id: u16, name: &str, unicast: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    encode_name(name, &mut b);
    b.extend_from_slice(&12u16.to_be_bytes());
    b.extend_from_slice(&(if unicast { 0x8001u16 } else { 1 }).to_be_bytes());
    b
}

/// Extract (ip, hostname) pairs from PTR and A records in any DNS message.
fn parse_records(buf: &[u8]) -> Vec<(Ipv4Addr, String)> {
    let mut out = Vec::new();
    let mut inner = || -> Option<()> {
        let qd = u16be(buf, 4)?;
        let rr = u16be(buf, 6)? as u32 + u16be(buf, 8)? as u32 + u16be(buf, 10)? as u32;
        let mut pos = 12;
        for _ in 0..qd {
            pos = read_name(buf, pos)?.1 + 4;
        }
        for _ in 0..rr {
            let (owner, p) = read_name(buf, pos)?;
            let ty = u16be(buf, p)?;
            let rdlen = u16be(buf, p + 8)? as usize;
            let rd = p + 10;
            let rdata = buf.get(rd..rd + rdlen)?;
            match ty {
                12 => {
                    if let (Some(ip), Some((target, _))) = (ip_from_reverse(&owner.to_lowercase()), read_name(buf, rd))
                    {
                        out.push((ip, target));
                    }
                }
                1 if rdlen == 4 => {
                    out.push((Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]), owner));
                }
                _ => {}
            }
            pos = rd + rdlen;
        }
        Some(())
    };
    let _ = inner();
    out.retain(|(_, n)| !n.is_empty());
    out
}

// ------------------------------------------------------------------- mDNS

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

fn mdns_socket(iface_ip: Ipv4Addr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    // Binding 5353 alongside avahi lets us hear multicast replies and
    // unsolicited announcements; fall back to an ephemeral port otherwise.
    if s.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5353).into()).is_err() {
        s.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    }
    let _ = s.join_multicast_v4(&MDNS_GROUP, &iface_ip);
    let _ = s.set_multicast_if_v4(&iface_ip);
    s.set_read_timeout(Some(Duration::from_millis(60)))?;
    Ok(s.into())
}

/// Reverse-resolve `hosts` over mDNS for `budget`, reporting each hit once.
pub fn mdns(iface_ip: Ipv4Addr, hosts: &[Ipv4Addr], budget: Duration, mut report: impl FnMut(Ipv4Addr, String)) {
    let Ok(sock) = mdns_socket(iface_ip) else { return };
    let wanted: HashSet<Ipv4Addr> = hosts.iter().copied().collect();
    let dst = SocketAddrV4::new(MDNS_GROUP, 5353);
    let send_all = |sock: &UdpSocket| {
        for (i, h) in hosts.iter().enumerate() {
            let _ = sock.send_to(&ptr_query(i as u16 + 1, &reverse_name(*h), true), dst);
        }
    };
    let start = Instant::now();
    send_all(&sock);
    let mut resent = false;
    let mut seen = HashSet::new();
    let mut buf = [0u8; 9000];
    while start.elapsed() < budget {
        if !resent && start.elapsed() > Duration::from_millis(400) {
            send_all(&sock);
            resent = true;
        }
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            for (ip, name) in parse_records(&buf[..n]) {
                if wanted.contains(&ip) && seen.insert((ip, name.clone())) {
                    report(ip, name);
                }
            }
        }
    }
}

// ---------------------------------------------------------------- NetBIOS

fn nbstat_query(id: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(50);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    b.push(0x20);
    b.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // "*" encoded
    b.push(0);
    b.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // NBSTAT, IN
    b
}

fn parse_nbstat(buf: &[u8]) -> Option<String> {
    if u16be(buf, 6)? == 0 {
        return None;
    }
    let (_, p) = read_name(buf, 12)?;
    let mut pos = p + 10;
    let n = *buf.get(pos)? as usize;
    pos += 1;
    let mut fallback = None;
    for i in 0..n {
        let e = buf.get(pos + i * 18..pos + i * 18 + 18)?;
        let name = String::from_utf8_lossy(&e[..15]).trim_end().to_string();
        let group = u16be(e, 16)? & 0x8000 != 0;
        if group || name.is_empty() || name.chars().any(|c| c.is_control()) {
            continue;
        }
        match e[15] {
            0x00 => return Some(name),
            0x20 if fallback.is_none() => fallback = Some(name),
            _ => {}
        }
    }
    fallback
}

/// NetBIOS node-status query to every host; Windows boxes answer with their name.
pub fn netbios(hosts: &[Ipv4Addr], budget: Duration, mut report: impl FnMut(Ipv4Addr, String)) {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else { return };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(60)));
    let start = Instant::now();
    let send_all = |sock: &UdpSocket| {
        for (i, h) in hosts.iter().enumerate() {
            let _ = sock.send_to(&nbstat_query(i as u16 + 1), (*h, 137));
        }
    };
    send_all(&sock);
    let mut resent = false;
    let mut seen = HashSet::new();
    let mut buf = [0u8; 2048];
    while start.elapsed() < budget {
        if !resent && start.elapsed() > Duration::from_millis(500) {
            send_all(&sock);
            resent = true;
        }
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let (IpAddr::V4(ip), Some(name)) = (from.ip(), parse_nbstat(&buf[..n])) {
                if seen.insert(ip) {
                    report(ip, name);
                }
            }
        }
    }
}

// -------------------------------------------------------------------- DNS

/// System reverse DNS (getnameinfo). Blocking; callers run it on a pool.
pub fn dns(ip: Ipv4Addr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok()?;
    (name != ip.to_string() && !name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names_round_trip() {
        let ip = Ipv4Addr::new(192, 168, 10, 144);
        assert_eq!(reverse_name(ip), "144.10.168.192.in-addr.arpa");
        assert_eq!(ip_from_reverse(&reverse_name(ip)), Some(ip));
        assert_eq!(ip_from_reverse("foo.local"), None);
    }

    #[test]
    fn parses_ptr_answer_with_compression() {
        // Build: question for 144.10.168.192.in-addr.arpa, answer PTR pointing
        // at "reachy-mini.local" with the owner name compressed (0xC00C).
        let mut q = ptr_query(7, "144.10.168.192.in-addr.arpa", false);
        q[7] = 1; // ancount = 1
        q.extend_from_slice(&[0xC0, 0x0C]); // owner -> offset 12
        q.extend_from_slice(&12u16.to_be_bytes()); // PTR
        q.extend_from_slice(&1u16.to_be_bytes()); // IN
        q.extend_from_slice(&120u32.to_be_bytes()); // TTL
        let mut rdata = Vec::new();
        encode_name("reachy-mini.local", &mut rdata);
        q.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        q.extend_from_slice(&rdata);
        let recs = parse_records(&q);
        assert_eq!(
            recs,
            vec![(Ipv4Addr::new(192, 168, 10, 144), "reachy-mini.local".to_string())]
        );
    }

    #[test]
    fn parses_a_record() {
        let mut m = vec![0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        encode_name("pi.local", &mut m);
        m.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 5]);
        assert_eq!(
            parse_records(&m),
            vec![(Ipv4Addr::new(10, 0, 0, 5), "pi.local".to_string())]
        );
    }

    #[test]
    fn parses_nbstat_reply() {
        let mut m = vec![0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        m.push(0x20);
        m.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        m.push(0);
        m.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0]); // type class ttl rdlen(ignored)
        m.push(2); // two names
        m.extend_from_slice(b"WORKGROUP      ");
        m.extend_from_slice(&[0x00, 0x84, 0x00]); // suffix 0x00, group flag set
        m.extend_from_slice(b"DESKTOP-42     ");
        m.extend_from_slice(&[0x00, 0x04, 0x00]); // suffix 0x00, unique
        assert_eq!(parse_nbstat(&m), Some("DESKTOP-42".to_string()));
    }
}
