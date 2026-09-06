//! Minimal DNS wire codec — just enough for fake-IP answering.
//!
//! Parses the single question of a UDP query (QNAME labels, QTYPE) and
//! builds A / AAAA / empty / NXDOMAIN responses that copy the question
//! section verbatim (preserving 0x20 case randomization). Compression
//! pointers in *queries* are rejected as malformed (well-behaved stub
//! resolvers never send them).

use std::net::{Ipv4Addr, Ipv6Addr};

/// QTYPE values we care about.
pub const QTYPE_A: u16 = 1;
pub const QTYPE_PTR: u16 = 12;
pub const QTYPE_AAAA: u16 = 28;

/// Fake answers advertise a 1-second TTL: the mapping (not the DNS
/// cache) is authoritative, and long TTLs would fight eviction.
pub const FAKE_TTL: u32 = 1;

/// A parsed DNS query (header + single question).
#[derive(Debug)]
pub struct DnsQuery<'a> {
    pub id: u16,
    /// Recursion Desired flag (copied into the response).
    pub rd: bool,
    /// Raw question bytes: QNAME labels + QTYPE + QCLASS, verbatim.
    pub question: &'a [u8],
    /// Decoded, lowercased QNAME (`a.b.example`).
    pub domain: String,
    pub qtype: u16,
}

/// Parse a UDP DNS query. Returns None on malformed input.
pub fn parse_query(buf: &[u8]) -> Option<DnsQuery<'_>> {
    if buf.len() < 17 {
        return None; // header (12) + at least 1+4 question bytes
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount != 1 {
        return None; // we only answer single-question queries
    }
    if flags & 0x8000 != 0 {
        return None; // QR set: this is a response, not a query
    }
    let rd = flags & 0x0100 != 0;

    // Decode QNAME starting at offset 12.
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut pos = 12usize;
    let mut total = 0usize; // encoded length budget
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer in query: reject
        }
        if len > 63 {
            return None; // label too long
        }
        pos += 1;
        let end = pos.checked_add(len)?;
        let label = buf.get(pos..end)?;
        labels.push(label);
        total += 1 + len;
        pos = end;
        if total > 254 {
            return None; // name exceeds 255 octets
        }
    }
    if buf.len() < pos + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let question = buf.get(12..pos + 4)?;

    let mut domain = String::new();
    for (i, label) in labels.iter().enumerate() {
        if i > 0 {
            domain.push('.');
        }
        domain.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
    }
    if domain.is_empty() {
        return None; // root query: not ours to fake
    }

    Some(DnsQuery { id, rd, question, domain, qtype })
}

/// Build the response header: QR=1, copied RD, RA=1, rcode.
fn header(q: &DnsQuery<'_>, ancount: u16, rcode: u16) -> [u8; 12] {
    let flags: u16 = 0x8000 // QR: response
        | 0x0080 // RA: recursion available
        | if q.rd { 0x0100 } else { 0 } // copy RD
        | (rcode & 0x000F);
    let mut h = [0u8; 12];
    h[0..2].copy_from_slice(&q.id.to_be_bytes());
    h[2..4].copy_from_slice(&flags.to_be_bytes());
    h[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    h[6..8].copy_from_slice(&ancount.to_be_bytes());
    // NSCOUNT / ARCOUNT stay zero.
    h
}

fn assemble(q: &DnsQuery<'_>, rcode: u16, answer: Option<&[u8]>) -> Vec<u8> {
    let an: u16 = if answer.is_some() { 1 } else { 0 };
    let mut out = Vec::with_capacity(12 + q.question.len() + answer.map_or(0, |a| a.len()));
    out.extend_from_slice(&header(q, an, rcode));
    out.extend_from_slice(q.question);
    if let Some(a) = answer {
        out.extend_from_slice(a);
    }
    out
}

/// A-record answer body: name pointer to question, A, IN, TTL, 4 bytes.
fn a_answer(ip: Ipv4Addr) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xC0;
    a[1] = 0x0C; // pointer to offset 12 (question name)
    a[2..4].copy_from_slice(&QTYPE_A.to_be_bytes());
    a[4..6].copy_from_slice(&1u16.to_be_bytes()); // IN
    a[6..10].copy_from_slice(&FAKE_TTL.to_be_bytes());
    a[10..12].copy_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    a[12..16].copy_from_slice(&ip.octets());
    a
}

/// AAAA-record answer body (28 bytes).
fn aaaa_answer(ip: Ipv6Addr) -> [u8; 28] {
    let mut a = [0u8; 28];
    a[0] = 0xC0;
    a[1] = 0x0C;
    a[2..4].copy_from_slice(&QTYPE_AAAA.to_be_bytes());
    a[4..6].copy_from_slice(&1u16.to_be_bytes());
    a[6..10].copy_from_slice(&FAKE_TTL.to_be_bytes());
    a[10..12].copy_from_slice(&16u16.to_be_bytes());
    a[12..28].copy_from_slice(&ip.octets());
    a
}

/// Response carrying a fake A record.
pub fn build_a_response(q: &DnsQuery<'_>, ip: Ipv4Addr) -> Vec<u8> {
    assemble(q, 0, Some(&a_answer(ip)))
}

/// A-record response with an explicit TTL (real answers).
pub fn build_a_response_ttl(q: &DnsQuery<'_>, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    assemble(q, 0, Some(&a_answer_ttl(ip, ttl)))
}

fn a_answer_ttl(ip: Ipv4Addr, ttl: u32) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xC0;
    a[1] = 0x0C;
    a[2..4].copy_from_slice(&QTYPE_A.to_be_bytes());
    a[4..6].copy_from_slice(&1u16.to_be_bytes());
    a[6..10].copy_from_slice(&ttl.to_be_bytes());
    a[10..12].copy_from_slice(&4u16.to_be_bytes());
    a[12..16].copy_from_slice(&ip.octets());
    a
}

/// Response carrying a fake AAAA record.
pub fn build_aaaa_response(q: &DnsQuery<'_>, ip: Ipv6Addr) -> Vec<u8> {
    assemble(q, 0, Some(&aaaa_answer(ip)))
}

/// AAAA-record response with an explicit TTL (real answers).
pub fn build_aaaa_response_ttl(q: &DnsQuery<'_>, ip: Ipv6Addr, ttl: u32) -> Vec<u8> {
    let mut a = [0u8; 28];
    a[0] = 0xC0;
    a[1] = 0x0C;
    a[2..4].copy_from_slice(&QTYPE_AAAA.to_be_bytes());
    a[4..6].copy_from_slice(&1u16.to_be_bytes());
    a[6..10].copy_from_slice(&ttl.to_be_bytes());
    a[10..12].copy_from_slice(&16u16.to_be_bytes());
    a[12..28].copy_from_slice(&ip.octets());
    assemble(q, 0, Some(&a))
}

/// NODATA response (rcode OK, zero answers) — e.g. AAAA when disabled.
pub fn build_empty_response(q: &DnsQuery<'_>) -> Vec<u8> {
    assemble(q, 0, None)
}

/// NXDOMAIN response — e.g. PTR queries against fake tokens.
pub fn build_nxdomain(q: &DnsQuery<'_>) -> Vec<u8> {
    assemble(q, 3, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built query: id 0xBEEF, RD, QNAME www.Example.COM, A, IN.
    fn query(qtype: u16) -> Vec<u8> {
        let mut b = vec![0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        b.extend_from_slice(b"\x03www\x07Example\x03com\x00");
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b
    }

    #[test]
    fn parses_query_and_lowercases() {
        let buf = query(QTYPE_A);
        let q = parse_query(&buf).expect("valid query");
        assert_eq!(q.id, 0xBEEF);
        assert!(q.rd);
        assert_eq!(q.domain, "www.example.com");
        assert_eq!(q.qtype, QTYPE_A);
        assert_eq!(q.question.len(), 17 + 4);
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_query(&[]).is_none());
        assert!(parse_query(&query(QTYPE_A)[..10]).is_none());
        let mut resp = query(QTYPE_A);
        resp[2] |= 0x80; // QR set
        assert!(parse_query(&resp).is_none());
        let mut two = query(QTYPE_A);
        two[5] = 2; // QDCOUNT=2
        assert!(parse_query(&two).is_none());
        // compression pointer in qname
        let mut comp = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1];
        comp[0] = 0;
        assert!(parse_query(&comp).is_none());
    }

    #[test]
    fn a_response_layout() {
        let buf = query(QTYPE_A);
        let q = parse_query(&buf).unwrap();
        let resp = build_a_response(&q, Ipv4Addr::new(198, 18, 0, 7));
        assert_eq!(resp.len(), 12 + q.question.len() + 16);
        assert_eq!(&resp[0..2], &[0xBE, 0xEF], "id copied");
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x8000, 0x8000, "QR set");
        assert_eq!(flags & 0x0100, 0x0100, "RD copied");
        assert_eq!(flags & 0x0080, 0x0080, "RA set");
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1, "QD=1");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "AN=1");
        // question copied verbatim (case preserved)
        assert_eq!(&resp[12..12 + q.question.len()], q.question);
        // answer name pointer
        assert_eq!(&resp[12 + q.question.len()..14 + q.question.len()], &[0xC0, 0x0C]);
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[198, 18, 0, 7], "rdata = fake ip");
    }

    #[test]
    fn aaaa_response_layout() {
        let buf = query(QTYPE_AAAA);
        let q = parse_query(&buf).unwrap();
        let ip: Ipv6Addr = "fc00::1".parse().unwrap();
        let resp = build_aaaa_response(&q, ip);
        assert_eq!(resp.len(), 12 + q.question.len() + 28);
        assert_eq!(&resp[resp.len() - 16..], &ip.octets());
    }

    #[test]
    fn empty_and_nxdomain() {
        let buf = query(QTYPE_PTR);
        let q = parse_query(&buf).unwrap();
        let nodata = build_empty_response(&q);
        assert_eq!(u16::from_be_bytes([nodata[6], nodata[7]]), 0, "no answers");
        let nx = build_nxdomain(&q);
        assert_eq!(u16::from_be_bytes([nx[2], nx[3]]) & 0x000F, 3, "rcode NXDOMAIN");
    }
}
