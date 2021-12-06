use log::warn;

use crate::types::{DnsHeader, DnsPacket, DnsQuestion, DnsRecord, QueryType};

struct BytePacketBuffer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BytePacketBuffer<'a> {
    /// This gives us a fresh buffer for holding the packet contents, and a
    /// field for keeping track of where we are.
    pub fn new(buffer: &'a mut [u8]) -> BytePacketBuffer<'a> {
        BytePacketBuffer {
            buf: buffer,
            pos: 0,
        }
    }

    fn write(&mut self, val: u8) -> anyhow::Result<()> {
        if self.pos >= 512 {
            anyhow::bail!("End of buffer")
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> anyhow::Result<()> {
        self.write(val)?;

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> anyhow::Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> anyhow::Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> anyhow::Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                anyhow::bail!("Single label exceeds 63 characters")
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> anyhow::Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> anyhow::Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}

pub fn write(buf: &mut [u8], packet: &DnsPacket) -> anyhow::Result<usize> {
    let mut buffer = BytePacketBuffer::new(buf);

    write_header(&packet.header, &mut buffer)?;

    for question in &packet.questions {
        write_question(&question, &mut buffer)?;
    }

    for rec in &packet.answers {
        write_record(rec, &mut buffer)?;
    }
    for rec in &packet.authorities {
        write_record(rec, &mut buffer)?;
    }
    for rec in &packet.resources {
        write_record(rec, &mut buffer)?;
    }

    Ok(buffer.pos)
}

fn write_header(header: &DnsHeader, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
    buffer.write_u16(header.id)?;
    buffer.write_u16(header.flags())?;
    buffer.write_u16(header.questions)?;
    buffer.write_u16(header.answers)?;
    buffer.write_u16(header.authoritative_entries)?;
    buffer.write_u16(header.resource_entries)?;

    Ok(())
}

fn write_question(question: &DnsQuestion, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
    buffer.write_qname(&question.name)?;
    let typenum = question.qtype.to_num();
    buffer.write_u16(typenum)?;
    buffer.write_u16(1)?;

    Ok(())
}

fn write_record(record: &DnsRecord, buffer: &mut BytePacketBuffer) -> anyhow::Result<usize> {
    let start_pos = buffer.pos;

    match *record {
        DnsRecord::A {
            ref domain,
            ref addr,
            ttl,
        } => {
            buffer.write_qname(domain)?;
            buffer.write_u16(QueryType::A.to_num())?;
            buffer.write_u16(1)?;
            buffer.write_u32(ttl)?;
            buffer.write_u16(4)?;

            let octets = addr.octets();
            buffer.write_u8(octets[0])?;
            buffer.write_u8(octets[1])?;
            buffer.write_u8(octets[2])?;
            buffer.write_u8(octets[3])?;
        }
        DnsRecord::NS {
            ref domain,
            ref host,
            ttl,
        } => {
            buffer.write_qname(domain)?;
            buffer.write_u16(QueryType::NS.to_num())?;
            buffer.write_u16(1)?;
            buffer.write_u32(ttl)?;

            let pos = buffer.pos;
            buffer.write_u16(0)?;

            buffer.write_qname(host)?;

            let size = buffer.pos - (pos + 2);
            buffer.set_u16(pos, size as u16)?;
        }
        DnsRecord::CNAME {
            ref domain,
            ref host,
            ttl,
        } => {
            buffer.write_qname(domain)?;
            buffer.write_u16(QueryType::CNAME.to_num())?;
            buffer.write_u16(1)?;
            buffer.write_u32(ttl)?;

            let pos = buffer.pos;
            buffer.write_u16(0)?;

            buffer.write_qname(host)?;

            let size = buffer.pos - (pos + 2);
            buffer.set_u16(pos, size as u16)?;
        }
        DnsRecord::MX {
            ref domain,
            priority,
            ref host,
            ttl,
        } => {
            buffer.write_qname(domain)?;
            buffer.write_u16(QueryType::MX.to_num())?;
            buffer.write_u16(1)?;
            buffer.write_u32(ttl)?;

            let pos = buffer.pos;
            buffer.write_u16(0)?;

            buffer.write_u16(priority)?;
            buffer.write_qname(host)?;

            let size = buffer.pos - (pos + 2);
            buffer.set_u16(pos, size as u16)?;
        }
        DnsRecord::AAAA {
            ref domain,
            ref addr,
            ttl,
        } => {
            buffer.write_qname(domain)?;
            buffer.write_u16(QueryType::AAAA.to_num())?;
            buffer.write_u16(1)?;
            buffer.write_u32(ttl)?;
            buffer.write_u16(16)?;

            for octet in &addr.segments() {
                buffer.write_u16(*octet)?;
            }
        }
        DnsRecord::UNKNOWN { .. } => {
            warn!("Skipping record: {:?}", record);
        }
    }

    Ok(buffer.pos - start_pos)
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;
    use std::net::Ipv4Addr;

    use crate::types::ResponseCode;

    use super::*;

    #[rustfmt::skip]
    fn google_answer() -> [u8; 54] {
        [
            0xa8, 0x4f, // identifier
            0x01, 0x20, // flags
            0x00, 0x01, // question count
            0x00, 0x01, // answer count
            0x00, 0x00, // authority count
            0x00, 0x00, // additional count
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com
            0x00, 0x01, // query type
            0x00, 0x01, // query question
            // Repeating this instead of adding jump
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com
            0x00, 0x01, // query type
            0x00, 0x01, // query class
            0x00, 0x00, 0x01, 0x25, // ttl
            0x00, 0x04, // len
            0xd8, 0x3a, 0xd3, 0x8e, // ip
        ]
    }

    fn google_header_answer() -> DnsHeader {
        DnsHeader {
            id: 43087, // 16 bits

            response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,

            recursion_available: false,
            z: false,
            authed_data: true,
            checking_disabled: false,
            rescode: ResponseCode::NOERROR,

            questions: 1,
            answers: 1,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    #[test]
    fn writing_works() {
        let header = google_header_answer();
        let question = DnsQuestion {
            name: "google.com".to_string(),
            qtype: QueryType::A,
        };
        let record = DnsRecord::A {
            domain: "google.com".to_string(),
            addr: Ipv4Addr::new(216, 58, 211, 142),
            ttl: 293,
        };

        let dns_packet = DnsPacket {
            header,
            questions: vec![question],
            answers: vec![record],
            authorities: vec![],
            resources: vec![],
        };

        let mut vec = vec![0u8; 512];
        let size = write(&mut vec, &dns_packet).unwrap();

        assert_eq!(&vec[..size], google_answer());
    }
}
