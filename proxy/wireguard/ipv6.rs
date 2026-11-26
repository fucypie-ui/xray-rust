//! IP-medium IPv6 fragment reassembly missing from smoltcp 0.14.
//! Called only after Noise authentication and source allowedIPs validation.
use std::{collections::{HashMap, hash_map::Entry}, time::{Duration, Instant}};

const MAX_ASSEMBLIES: usize = 16;
const MAX_FRAGMENTS: usize = 128;
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key { addresses: [u8; 32], id: u32 }
struct Assembly {
    created: Instant,
    prefix_len: usize,
    next_header: u8,
    header: Option<Vec<u8>>,
    data: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    received: usize,
    nonfinal_end: usize,
    total: Option<usize>,
    invalid: bool,
}
impl Assembly {
    fn invalidate(&mut self) {
        // Retain the key until expiry: later fragments cannot resurrect an
        // overlapping datagram (RFC 5722). Release its payload immediately.
        self.invalid = true;
        self.header = None;
        self.data = Vec::new();
        self.ranges = Vec::new();
    }
}

#[derive(Default)]
pub(super) struct Ipv6Reassembler { assemblies: HashMap<Key, Assembly> }
impl Ipv6Reassembler {
    pub fn expire(&mut self, now: Instant) {
        self.assemblies.retain(|_, entry| now.duration_since(entry.created) < REASSEMBLY_TIMEOUT);
    }
    pub fn clear(&mut self) { self.assemblies.clear(); }

    pub fn process(&mut self, mut packet: Vec<u8>, now: Instant) -> Option<Vec<u8>> {
        self.expire(now);
        if packet.first()? >> 4 != 6 { return Some(packet); }
        if packet.len() < 40 { return None; }
        let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
        let packet_len = 40 + payload_len;
        if packet.len() < packet_len { return None; }
        packet.truncate(packet_len);
        let (mut previous, mut offset, mut next) = (6, 40, packet[6]);
        // Preserve any unfragmentable extension headers and repair the field
        // which points to the removed Fragment header. Unsupported transport
        // or extension headers remain subject to smoltcp's normal validation.
        for _ in 0..8 {
            match next {
                44 => break,
                0 | 43 | 60 => {
                    let header = packet.get(offset..offset + 2)?;
                    next = header[0];
                    previous = offset;
                    offset += (usize::from(header[1]) + 1) * 8;
                    if offset > packet.len() { return None; }
                }
                _ => return Some(packet),
            }
        }
        if next != 44 { return None; }
        let fragment = packet.get(offset..offset + 8)?;
        let next_header = fragment[0];
        let flags = u16::from_be_bytes([fragment[2], fragment[3]]);
        let start = usize::from(flags & 0xfff8);
        let more = flags & 1 != 0;
        let key = Key { addresses: packet[8..40].try_into().ok()?,
            id: u32::from_be_bytes(fragment[4..8].try_into().ok()?) };
        let data = &packet[offset + 8..];
        let end = start + data.len();
        // IPv6 jumbograms cannot be fragmented. Nonfinal fragments consist
        // of whole eight-octet units; reserved bits are ignored on reception.
        if data.is_empty() || (more && !data.len().is_multiple_of(8))
            || offset - 40 + end > u16::MAX as usize || next_header == 44 {
            if let Some(entry) = self.assemblies.get_mut(&key) { entry.invalidate(); }
            return None;
        }
        if start == 0 && !more {
            // RFC 6946 atomic fragments are independent of queued assemblies.
            packet[previous] = next_header;
            packet.drain(offset..offset + 8);
            packet[4..6].copy_from_slice(&((payload_len - 8) as u16).to_be_bytes());
            return Some(packet);
        }
        let at_capacity = self.assemblies.len() >= MAX_ASSEMBLIES;
        let entry = match self.assemblies.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                if at_capacity { return None; }
                entry.insert(Assembly { created: now, prefix_len: offset, next_header,
                    header: None, data: Vec::new(), ranges: Vec::new(), received: 0,
                    nonfinal_end: 0, total: None, invalid: false })
            }
        };
        if entry.invalid { return None; }
        if entry.prefix_len != offset || entry.next_header != next_header
            || entry.ranges.len() >= MAX_FRAGMENTS
            || entry.ranges.iter().any(|&(left, right)| start < right && end > left)
            || entry.total.is_some_and(|total| end > total || (more && end >= total))
            || (!more && (entry.total.is_some_and(|total| total != end)
                || entry.data.len() > end || entry.nonfinal_end >= end)) {
            entry.invalidate();
            return None;
        }
        if start == 0 {
            let mut header = packet[..offset].to_vec();
            header[previous] = next_header;
            entry.header = Some(header);
        }
        if more { entry.nonfinal_end = entry.nonfinal_end.max(end); }
        else { entry.total = Some(end); }
        entry.data.resize(entry.data.len().max(end), 0);
        entry.data[start..end].copy_from_slice(data);
        entry.ranges.push((start, end));
        entry.received += data.len();
        if entry.total != Some(entry.received) || entry.header.is_none() { return None; }
        let entry = self.assemblies.remove(&key)?;
        let mut packet = entry.header?;
        let payload_len = packet.len() - 40 + entry.data.len();
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet.extend_from_slice(&entry.data);
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(id: u32, offset: u16, more: bool, data: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((data.len() + 8) as u16).to_be_bytes());
        packet[6] = 44; packet[7] = 64;
        packet[8..24].copy_from_slice(&"fd77::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"fd77::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet[40] = 17;
        packet[42..44].copy_from_slice(&(offset | u16::from(more)).to_be_bytes());
        packet[44..48].copy_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(data);
        packet
    }

    #[test]
    fn reordered_fragments_preserve_every_byte_and_remove_fragment_header() {
        let now = Instant::now();
        let mut reassembly = Ipv6Reassembler::default();
        assert!(reassembly.process(fragment(7, 16, false, b"tail"), now).is_none());
        assert!(reassembly.process(fragment(7, 8, true, b"middle!!"), now).is_none());
        let packet = reassembly.process(fragment(7, 0, true, b"header!!"), now).unwrap();
        assert_eq!(packet[6], 17);
        assert_eq!(&packet[4..6], &20u16.to_be_bytes());
        assert_eq!(&packet[40..], b"header!!middle!!tail");
        assert!(reassembly.assemblies.is_empty());
    }

    #[test]
    fn overlaps_poison_the_whole_datagram_until_expiry() {
        let now = Instant::now();
        let mut reassembly = Ipv6Reassembler::default();
        let first = fragment(7, 0, true, &[1; 16]);
        assert!(reassembly.process(first.clone(), now).is_none());
        assert!(reassembly.process(fragment(7, 8, true, &[2; 8]), now).is_none());
        assert!(reassembly.process(fragment(7, 16, false, &[3; 8]), now).is_none());
        assert!(reassembly.process(first.clone(), now).is_none());
        assert!(reassembly.assemblies.values().all(|entry| entry.invalid && entry.data.is_empty()));
        let later = now + REASSEMBLY_TIMEOUT;
        assert!(reassembly.process(first, later).is_none());
        assert!(reassembly.process(fragment(7, 16, false, &[3; 8]), later).is_some());
    }

    #[test]
    fn atomic_fragments_do_not_interfere_with_queued_same_id() {
        let now = Instant::now();
        let mut reassembly = Ipv6Reassembler::default();
        assert!(reassembly.process(fragment(7, 0, true, &[1; 8]), now).is_none());
        let atomic = reassembly.process(fragment(7, 0, false, &[2; 8]), now).unwrap();
        assert_eq!(&atomic[40..], &[2; 8]);
        let queued = reassembly.process(fragment(7, 8, false, &[3; 8]), now).unwrap();
        assert_eq!(&queued[40..48], &[1; 8]);
        assert_eq!(&queued[48..], &[3; 8]);
    }

    #[test]
    fn hop_by_hop_prefix_is_preserved_and_its_next_header_is_repaired() {
        let now = Instant::now();
        let mut reassembly = Ipv6Reassembler::default();
        let with_prefix = |mut packet: Vec<u8>| {
            packet[6] = 0;
            packet.splice(40..40, [44, 0, 1, 4, 0, 0, 0, 0]);
            let length = (packet.len() - 40) as u16;
            packet[4..6].copy_from_slice(&length.to_be_bytes());
            packet
        };
        assert!(reassembly.process(with_prefix(fragment(7, 8, false, &[2; 8])), now).is_none());
        let packet = reassembly.process(with_prefix(fragment(7, 0, true, &[1; 8])), now).unwrap();
        assert_eq!(packet[6], 0);
        assert_eq!(&packet[40..48], &[17, 0, 1, 4, 0, 0, 0, 0]);
        assert_eq!(&packet[4..6], &24u16.to_be_bytes());
        assert_eq!(&packet[48..56], &[1; 8]);
        assert_eq!(&packet[56..], &[2; 8]);
    }

    #[test]
    fn fragment_count_limit_invalidates_without_growing_buffers() {
        let now = Instant::now();
        let mut reassembly = Ipv6Reassembler::default();
        for index in 0..MAX_FRAGMENTS {
            assert!(reassembly.process(fragment(7, (index * 8) as u16, true, &[1; 8]), now).is_none());
        }
        assert!(reassembly.process(fragment(7, (MAX_FRAGMENTS * 8) as u16, false, &[1; 8]), now).is_none());
        assert!(reassembly.assemblies.values().all(|entry| entry.invalid && entry.data.is_empty()));
    }

    #[test]
    fn malformed_lengths_conflicting_final_sizes_and_capacity_are_bounded() {
        let now = Instant::now();
        let mut reassembly = Ipv6Reassembler::default();
        assert!(reassembly.process(fragment(1, 0, true, &[1; 7]), now).is_none());
        assert!(reassembly.process(fragment(1, 65528, false, &[1; 8]), now).is_none());
        let mut truncated = fragment(1, 0, true, &[1; 8]); truncated.pop();
        assert!(reassembly.process(truncated, now).is_none());
        assert!(reassembly.process(fragment(1, 16, false, &[1; 8]), now).is_none());
        assert!(reassembly.process(fragment(1, 8, false, &[1; 8]), now).is_none());
        assert!(reassembly.assemblies.values().all(|entry| entry.invalid));
        reassembly.clear();
        for id in 0..MAX_ASSEMBLIES as u32 + 1 {
            assert!(reassembly.process(fragment(id, 0, true, &[1; 8]), now).is_none());
        }
        assert_eq!(reassembly.assemblies.len(), MAX_ASSEMBLIES);
        reassembly.expire(now + REASSEMBLY_TIMEOUT);
        assert!(reassembly.assemblies.is_empty());
    }
}
