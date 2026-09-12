#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

//! Splits the first TLS ClientHello segment of selected flows into a tiny
//! leading segment plus the remainder, so a reassembling DPI box never
//! classifies the flow as TLS and never sees the SNI it would reset on.

use std::fs;
use std::ops::Range;
use std::time::SystemTime;

#[cfg(target_os = "linux")]
use {
    nfq::{Queue, Verdict},
    socket2::{Domain, Protocol, SockAddr, Socket, Type},
    std::io,
    std::net::{Ipv4Addr, SocketAddrV4},
};

/// Matches `meta mark & 0x40000000` in deploy/byesni.nft, so our own raw
/// sends are not queued back to us.
const MARK: u32 = 0x4000_0000;
const MTU: usize = 1500;
#[cfg(target_os = "linux")]
const IPPROTO_RAW: i32 = 255;

struct Hostlist {
    path: String,
    stamp: Option<SystemTime>,
    names: Vec<String>,
}

impl Hostlist {
    fn new(path: String) -> Self {
        Self { path, stamp: None, names: Vec::new() }
    }

    fn matches(&mut self, sni: &str) -> bool {
        self.refresh();
        self.names.iter().any(|n| sni == n || sni.ends_with(&format!(".{n}")))
    }

    fn refresh(&mut self) {
        let stamp = fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if stamp == self.stamp {
            return;
        }
        self.stamp = stamp;
        self.names = fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim().to_ascii_lowercase())
            .filter(|l| !l.is_empty())
            .collect();
        eprintln!("byesni: loaded {} hostnames from {}", self.names.len(), self.path);
    }
}

fn ones(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [tail] = chunks.remainder() {
        sum += (*tail as u32) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn be16(data: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]) as usize)
}

fn sni(payload: &[u8]) -> Option<&str> {
    if payload.len() < 44 || payload[0] != 0x16 || payload[1] != 0x03 || payload[5] != 0x01 {
        return None;
    }
    let mut i = 43;
    i += 1 + *payload.get(i)? as usize;
    i += 2 + be16(payload, i)?;
    i += 1 + *payload.get(i)? as usize;
    let end = i + 2 + be16(payload, i)?;
    i += 2;
    while i + 4 <= end.min(payload.len()) {
        let kind = be16(payload, i)?;
        let len = be16(payload, i + 2)?;
        i += 4;
        if kind == 0 {
            let name = be16(payload, i + 3)?;
            return std::str::from_utf8(payload.get(i + 5..i + 5 + name)?).ok();
        }
        i += len;
    }
    None
}

/// Rebuilds `pkt` as a `first`-byte segment followed by MTU-sized remainders,
/// fixing length, IP id, sequence, PSH placement and both checksums.
fn segments(pkt: &[u8], ihl: usize, doff: usize, first: usize) -> Vec<Vec<u8>> {
    let (header, payload) = pkt.split_at(ihl + doff);
    let seq = u32::from_be_bytes(header[ihl + 4..ihl + 8].try_into().unwrap());
    let id = u16::from_be_bytes(header[4..6].try_into().unwrap());
    let flags = header[ihl + 13];

    let mut ranges: Vec<Range<usize>> = Vec::new();
    let mut at = 0;
    let mut want = first;
    while at < payload.len() {
        let take = want.min(payload.len() - at);
        ranges.push(at..at + take);
        at += take;
        want = MTU - ihl - doff;
    }

    ranges
        .iter()
        .enumerate()
        .map(|(n, part)| {
            let mut buf = Vec::with_capacity(header.len() + part.len());
            buf.extend_from_slice(header);
            buf.extend_from_slice(&payload[part.clone()]);
            let total = buf.len();
            buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            buf[4..6].copy_from_slice(&id.wrapping_add(n as u16).to_be_bytes());
            buf[ihl + 4..ihl + 8]
                .copy_from_slice(&seq.wrapping_add(part.start as u32).to_be_bytes());
            buf[ihl + 13] = if n + 1 == ranges.len() { flags } else { flags & !0x08 };

            buf[10..12].fill(0);
            let checksum = fold(ones(0, &buf[..ihl]));
            buf[10..12].copy_from_slice(&checksum.to_be_bytes());

            buf[ihl + 16..ihl + 18].fill(0);
            let pseudo = ones(0, &buf[12..20]) + 6 + (total - ihl) as u32;
            let checksum = fold(ones(pseudo, &buf[ihl..]));
            buf[ihl + 16..ihl + 18].copy_from_slice(&checksum.to_be_bytes());
            buf
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn decide(pkt: &[u8], first: usize, hosts: &mut Hostlist, sock: &Socket) -> Verdict {
    let Some(&version) = pkt.first() else { return Verdict::Accept };
    let ihl = (version & 0xf) as usize * 4;
    if version >> 4 != 4 || ihl < 20 || pkt.len() < ihl + 20 || pkt[9] != 6 {
        return Verdict::Accept;
    }
    let doff = (pkt[ihl + 12] >> 4) as usize * 4;
    if doff < 20 || pkt.len() <= ihl + doff + first {
        return Verdict::Accept;
    }
    let Some(name) = sni(&pkt[ihl + doff..]).map(str::to_ascii_lowercase) else {
        return Verdict::Accept;
    };
    if !hosts.matches(&name) {
        return Verdict::Accept;
    }

    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[16..20]).unwrap());
    let target = SockAddr::from(SocketAddrV4::new(dst, 0));
    let parts = segments(pkt, ihl, doff, first);
    for part in &parts {
        if let Err(e) = sock.send_to(part, &target) {
            eprintln!("byesni: raw send to {dst} failed, passing {name} through: {e}");
            return Verdict::Accept;
        }
    }
    eprintln!("byesni: split {name} into {} segments at {first}", parts.len());
    Verdict::Drop
}

#[cfg(target_os = "linux")]
fn main() -> io::Result<()> {
    let mut queue_num = 200;
    let mut first = 3;
    let mut path = String::from("/etc/byesni/hosts");
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().unwrap_or_default();
        match flag.as_str() {
            "--queue" => queue_num = value.parse().expect("--queue takes a number"),
            "--split" => first = value.parse().expect("--split takes a number"),
            "--hosts" => path = value,
            _ => {
                eprintln!("usage: byesni [--queue N] [--split N] [--hosts PATH]");
                std::process::exit(2);
            }
        }
    }

    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
    sock.set_mark(MARK)?;
    let mut hosts = Hostlist::new(path);
    hosts.refresh();

    let mut queue = Queue::open()?;
    queue.bind(queue_num)?;
    eprintln!("byesni: queue {queue_num}, split at {first}");
    loop {
        let mut msg = queue.recv()?;
        let verdict = decide(msg.get_payload(), first, &mut hosts, &sock);
        msg.set_verdict(verdict);
        queue.verdict(msg)?;
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("byesni is a Linux gateway daemon; `cargo test` covers the packet logic here");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(host: &str) -> Vec<u8> {
        let mut ext = vec![0x00, 0x00];
        let name = host.as_bytes();
        let entry = [&[0u8][..], &(name.len() as u16).to_be_bytes()[..], name].concat();
        let list = [&(entry.len() as u16).to_be_bytes()[..], &entry].concat();
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0xab; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn packet(payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0];
        pkt.extend_from_slice(&[192, 168, 10, 50]);
        pkt.extend_from_slice(&[23, 15, 142, 182]);
        pkt.extend_from_slice(&[0xc0, 0x00, 0x01, 0xbb]);
        pkt.extend_from_slice(&1000u32.to_be_bytes());
        pkt.extend_from_slice(&2000u32.to_be_bytes());
        pkt.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        pkt.extend_from_slice(payload);
        let total = (pkt.len() as u16).to_be_bytes();
        pkt[2..4].copy_from_slice(&total);
        pkt
    }

    #[test]
    fn parses_sni_and_ignores_non_hellos() {
        assert_eq!(sni(&client_hello("store.steampowered.com")), Some("store.steampowered.com"));
        assert_eq!(sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(sni(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01]), None);
        // Truncated at every length must refuse rather than panic or read past.
        let hello = client_hello("store.steampowered.com");
        for n in 0..hello.len() {
            assert_ne!(sni(&hello[..n]), Some("store.steampowered.com"));
        }
    }

    #[test]
    fn splits_preserving_the_byte_stream() {
        let payload = client_hello("store.steampowered.com");
        let pkt = packet(&payload);
        let parts = segments(&pkt, 20, 20, 3);

        assert_eq!(parts.len(), 2);
        assert_eq!(&parts[0][40..], &payload[..3]);
        assert_eq!(&parts[1][40..], &payload[3..]);
        assert_eq!(u32::from_be_bytes(parts[0][24..28].try_into().unwrap()), 1000);
        assert_eq!(u32::from_be_bytes(parts[1][24..28].try_into().unwrap()), 1003);
        assert_eq!(parts[0][33] & 0x08, 0, "PSH belongs on the last segment only");
        assert_eq!(parts[1][33] & 0x08, 0x08);

        for part in &parts {
            assert_eq!(u16::from_be_bytes(part[2..4].try_into().unwrap()) as usize, part.len());
            assert_eq!(fold(ones(0, &part[..20])), 0, "IP checksum");
            let pseudo = ones(0, &part[12..20]) + 6 + (part.len() - 20) as u32;
            assert_eq!(fold(ones(pseudo, &part[20..])), 0, "TCP checksum");
        }
    }

    #[test]
    fn chunks_oversized_payloads_under_the_mtu() {
        let mut payload = client_hello("store.steampowered.com");
        payload.resize(4000, 0x5a);
        let parts = segments(&packet(&payload), 20, 20, 3);

        assert!(parts.iter().all(|p| p.len() <= MTU));
        let rebuilt: Vec<u8> = parts.iter().flat_map(|p| p[40..].to_vec()).collect();
        assert_eq!(rebuilt, payload, "split must preserve the byte stream exactly");
    }
}
