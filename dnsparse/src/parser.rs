use std::{
    cmp::min_by_key,
    convert::TryFrom,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{
    types::{DnsHeader, DnsPacket, DnsQuestion, DnsRecord, QueryType, ResponseCode},
    utils::isperse,
};
use log::trace;
use nom::{
    bytes::{complete::take as take_bytes, complete::take_while},
    error::ParseError,
    multi::{count, many0},
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};

const JUMP_REQUIRED_FLAG: u8 = 0xc0;
const NULL_BYTE: u8 = 0x00;

fn ipv4<'a, E>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Ipv4Addr, E>
where
    E: ParseError<&'a [u8]>,
{
    |rest| {
        let (rest, quad0) = be_u8(rest)?;
        let (rest, quad1) = be_u8(rest)?;
        let (rest, quad2) = be_u8(rest)?;
        let (rest, quad3) = be_u8(rest)?;

        let ip = Ipv4Addr::new(quad0, quad1, quad2, quad3);

        Ok((rest, ip))
    }
}

#[allow(clippy::many_single_char_names)]
fn ipv6<'a, E>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Ipv6Addr, E>
where
    E: ParseError<&'a [u8]>,
{
    |rest| {
        let (rest, a) = be_u16(rest)?;
        let (rest, b) = be_u16(rest)?;
        let (rest, c) = be_u16(rest)?;
        let (rest, d) = be_u16(rest)?;
        let (rest, e) = be_u16(rest)?;
        let (rest, f) = be_u16(rest)?;
        let (rest, g) = be_u16(rest)?;
        let (rest, h) = be_u16(rest)?;

        let ip = Ipv6Addr::new(a, b, c, d, e, f, g, h);

        Ok((rest, ip))
    }
}

fn domain_fragment<'a, E>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], String, E>
where
    E: ParseError<&'a [u8]>,
{
    |input| {
        let (rest, size) = be_u8(input)?;
        let (rest, name) = take_bytes(size as usize)(rest)?;

        Ok((rest, String::from_utf8_lossy(name).to_string()))
    }
}

// TODO: Refactor this crap
fn domain_name<'a, E>(original: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], String, E>
where
    E: ParseError<&'a [u8]>,
{
    move |input| {
        // Parse upto shorter
        // (need a parser combinator which terminates at parser which finishes first)
        let o0xc0 = take_while(|c| c != JUMP_REQUIRED_FLAG)(input)?;
        let o0x00 = take_while(|c| c != NULL_BYTE)(input)?;
        let (rest, domain_name_bytes) = min_by_key(o0x00, o0xc0, |(_rest, parsed)| parsed.len());

        trace!("0x00 {:x?}", o0x00);
        trace!("0xc0 {:x?}", o0xc0);
        trace!("seclected {:x?}", (rest, domain_name_bytes));
        // trace!();

        let (_, mut fragments) = many0(domain_fragment())(domain_name_bytes)?;
        trace!("fragments: {:x?}", fragments);

        let (rest, next) = be_u8(rest)?;

        if next == JUMP_REQUIRED_FLAG {
            trace!("JUMPING");
            let (rest, jump_location) = be_u8(rest)?;

            let new_input = &original[(jump_location as usize)..];
            let (_ignore_rest, recursive_domain_str) = domain_name(original)(new_input)?;
            fragments.push(recursive_domain_str);

            let domain = isperse(fragments);
            trace!("Result (after jump): {}, Remaining: {:x?}", domain, rest);

            Ok((rest, domain))
        } else if next == NULL_BYTE {
            let domain = isperse(fragments);
            trace!("Result (no-jump): {}", domain);

            Ok((rest, domain))
        } else {
            panic!(
                "Impossible state reached, expecting {} or {}",
                NULL_BYTE, JUMP_REQUIRED_FLAG
            )
        }
    }
}

fn header<'a, E>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], DnsHeader, E>
where
    E: ParseError<&'a [u8]>,
{
    |input| {
        // network order is big endian
        let (rest, id) = be_u16(input)?;

        let (rest, a) = be_u8(rest)?;
        let (rest, b) = be_u8(rest)?;

        // Not sure how to do this bit fiddling with nom
        let recursion_desired = (a & (1 << 0)) > 0;
        let truncated_message = (a & (1 << 1)) > 0;
        let authoritative_answer = (a & (1 << 2)) > 0;
        let opcode = (a >> 3) & 0x0F;
        let response = (a & (1 << 7)) > 0;
        let rescode = ResponseCode::from_num(b & 0x0F);
        let checking_disabled = (b & (1 << 4)) > 0;
        let authed_data = (b & (1 << 5)) > 0;
        let z = (b & (1 << 6)) > 0;
        let recursion_available = (b & (1 << 7)) > 0;

        let (rest, questions) = be_u16(rest)?;
        let (rest, answers) = be_u16(rest)?;
        let (rest, authoritative_entries) = be_u16(rest)?;
        let (rest, resource_entries) = be_u16(rest)?;

        let dns_header = DnsHeader {
            id,

            response,
            opcode,
            authoritative_answer,
            truncated_message,
            recursion_desired,

            recursion_available,
            z,
            authed_data,
            checking_disabled,
            rescode,

            questions,
            answers,
            authoritative_entries,
            resource_entries,
        };

        Ok((rest, dns_header))
    }
}

fn question<'a, E>(original: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], DnsQuestion, E>
where
    E: ParseError<&'a [u8]>,
{
    move |input| {
        let (rest, domain) = domain_name(original)(input)?;
        let (rest, qtype) = be_u16(rest)?;
        let (rest, _qclass) = be_u16(rest)?;

        let question = DnsQuestion {
            name: domain,
            qtype: QueryType::from_num(qtype),
        };

        Ok((rest, question))
    }
}

fn answer<'a, E>(original: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], DnsRecord, E>
where
    E: ParseError<&'a [u8]>,
{
    move |input| {
        let (rest, domain) = domain_name(original)(input)?;
        let (rest, qnum) = be_u16(rest)?;
        let (rest, _qclass) = be_u16(rest)?;
        let (rest, ttl) = be_u32(rest)?;
        let (rest, data_len) = be_u16(rest)?;

        let qtype = QueryType::from_num(qnum);
        let (rest, record_bytes) = take_bytes(data_len as usize)(rest)?;

        let record = match qtype {
            QueryType::UNKNOWN(_) => DnsRecord::UNKNOWN {
                domain,
                qtype: qnum,
                data_len,
                ttl,
            },
            QueryType::A => {
                let (_rest, addr) = ipv4()(record_bytes)?;
                DnsRecord::A { domain, addr, ttl }
            }
            QueryType::CNAME => {
                let (_rest, host) = domain_name(original)(record_bytes)?;
                DnsRecord::CNAME { domain, host, ttl }
            }
            QueryType::NS => {
                let (_rest, host) = domain_name(original)(record_bytes)?;
                DnsRecord::NS { domain, host, ttl }
            }
            QueryType::MX => {
                let (rest, priority) = be_u16(record_bytes)?;
                let (_rest, host) = domain_name(original)(rest)?;
                DnsRecord::MX {
                    domain,
                    host,
                    ttl,
                    priority,
                }
            }
            QueryType::AAAA => {
                let (_rest, addr) = ipv6()(record_bytes)?;
                DnsRecord::AAAA { domain, addr, ttl }
            }
        };

        Ok((rest, record))
    }
}

pub fn packet<'a>(input: &'a [u8], original: &'a [u8]) -> IResult<&'a [u8], DnsPacket> {
    let (rest, header) = header()(input)?;
    let (rest, questions) = count(question(original), header.questions as usize)(rest)?;
    let (rest, answers) = count(answer(original), header.answers as usize)(rest)?;
    let (rest, authorities) = count(answer(original), header.authoritative_entries as usize)(rest)?;
    let (rest, resources) = count(answer(original), header.resource_entries as usize)(rest)?;

    let dns_packet = DnsPacket {
        header,
        questions,
        answers,
        authorities,
        resources,
    };

    Ok((rest, dns_packet))
}

impl<'a> TryFrom<&'a [u8]> for DnsPacket {
    type Error = String;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        match packet(&value, &value) {
            Ok(([], cl)) => Ok(cl),
            Ok((s, _)) => Err(format!(
                "Parsing Error: Unable to parse the whole dns packet\nRemaining Tokens: {:?}",
                s
            )),
            Err(e) => Err(format!("Parsing Error: {:?}", e)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    fn header(input: &[u8]) -> IResult<&[u8], DnsHeader> {
        super::header()(input)
    }

    fn question(input: &[u8]) -> IResult<&[u8], DnsQuestion> {
        super::question(&(*input))(input)
    }

    fn answer<'a>(input: &'a [u8], original: &'a [u8]) -> IResult<&'a [u8], DnsRecord> {
        super::answer(original)(input)
    }

    fn fragment(input: &[u8]) -> IResult<&[u8], String> {
        super::domain_fragment()(input)
    }

    fn domain(input: &[u8]) -> IResult<&[u8], String> {
        super::domain_name(input)(input)
    }

    #[rustfmt::skip]
    fn google_query() -> [u8; 28] {
        [
            0xa8, 0x4f, // identifier
            0x01, 0x20, // flags
            0x00, 0x01, // question count
            0x00, 0x00, // answer count
            0x00, 0x00, // authority count
            0x00, 0x00, // additional count
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com
            0x00, 0x01, // query type
            0x00, 0x01, // query question
        ]
    }

    #[rustfmt::skip]
    fn google_answer() -> [u8; 44] {
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
            0xc0, 0x0c, // name (Jump point)
            0x00, 0x01, // query type
            0x00, 0x01, // query class
            0x00, 0x00, 0x01, 0x25, // ttl
            0x00, 0x04, // len
            0xd8, 0x3a, 0xd3, 0x8e, // ip
        ]
    }

    fn google_header_question() -> DnsHeader {
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
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
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
    fn dns_header_parsing_works() {
        let (_, result) = header(&google_query()[..12]).unwrap();

        assert_eq!(result, google_header_question());
    }

    #[test]
    fn single_fragment_parsing_works() {
        let (_, result) = fragment(&google_query()[12..]).unwrap();

        assert_eq!(result, "google");
    }

    #[test]
    fn domain_name_parsing_works() {
        let (_, result) = domain(&google_query()[12..]).unwrap();

        assert_eq!(result, "google.com");
    }

    #[test]
    fn dns_question_parsing_works() {
        let expected_question = DnsQuestion {
            name: "google.com".to_string(),
            qtype: QueryType::A,
        };
        let (_, result) = question(&google_query()[12..]).unwrap();

        assert_eq!(result, expected_question);
    }

    #[test]
    fn dns_answer_parsing_works() {
        let record = DnsRecord::A {
            domain: "google.com".to_string(),
            addr: Ipv4Addr::new(216, 58, 211, 142),
            ttl: 293,
        };

        let (_, result) = answer(&google_answer()[28..], &google_answer()).unwrap();

        assert_eq!(result, record);
    }

    #[test]
    fn dns_packet_parsing_works_on_answer() {
        let header = google_header_answer();
        let expected_question = DnsQuestion {
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
            questions: vec![expected_question],
            answers: vec![record],
            authorities: vec![],
            resources: vec![],
        };

        let (_, result) = packet(&google_answer(), &google_answer()).unwrap();

        assert_eq!(result, dns_packet);
    }

    #[test]
    fn dns_packet_parsing_works_on_question() {
        let header = google_header_question();
        let expected_question = DnsQuestion {
            name: "google.com".to_string(),
            qtype: QueryType::A,
        };

        let dns_packet = DnsPacket {
            header,
            questions: vec![expected_question],
            answers: vec![],
            authorities: vec![],
            resources: vec![],
        };

        let (_, result) = packet(&google_query(), &google_query()).unwrap();

        assert_eq!(result, dns_packet);
    }

    #[rustfmt::skip]
    fn yahoo_packet() -> [u8; 95] {
         [
            0x03, 0x32, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, // header
            0x03, 0x77, 0x77, 0x77, 0x05, 0x79, 0x61, 0x68, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, // www.yahoo.com
            0x00, 0x01, 0x00, 0x01, // query type and query question
            // answers 1
            0xc0, 0x0c, //jump_location
            0x00, 0x05, 0x00, 0x01, // query type and query class
            0x00, 0x00, 0x00, 0x13, // ttl
            0x00, 0x14, // len
            // canonical name (notice the jump at the end to yahoo.com location (just after www))
            0x0b, 0x6e, 0x65, 0x77, 0x2d, 0x66, 0x70, 0x2d, 0x73, 0x68, 0x65, 0x64, 0x03, 0x77, 0x67, 0x31, 0x01, 0x62, 0xc0, 0x10,
            // answer 2
            0xc0, 0x2b, // jump location
            0x00, 0x01, 0x00, 0x01, // query type and query class
            0x00, 0x00, 0x00, 0x14, // ttl
            0x00, 0x04, // len
            0xca, 0xa5, 0x6b, 0x32, // ip
            // answer 3
            0xc0, 0x2b, // jump location
            0x00, 0x01, 0x00, 0x01, // query type and query class
            0x00, 0x00, 0x00, 0x14, // ttl
            0x00, 0x04, // len
            0xca, 0xa5, 0x6b, 0x31, // ip
        ]

    }

    #[test]
    fn dns_answer_complicated_parse() {
        let header = DnsHeader {
            id: 818,
            recursion_desired: true,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: true,
            rescode: ResponseCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: true,
            questions: 1,
            answers: 3,
            authoritative_entries: 0,
            resource_entries: 0,
        };
        let question = DnsQuestion {
            name: "www.yahoo.com".to_string(),
            qtype: QueryType::A,
        };
        let records = vec![
            DnsRecord::CNAME {
                domain: "www.yahoo.com".to_string(),
                host: "new-fp-shed.wg1.b.yahoo.com".to_string(),
                ttl: 19,
            },
            DnsRecord::A {
                domain: "new-fp-shed.wg1.b.yahoo.com".to_string(),
                addr: Ipv4Addr::new(202, 165, 107, 50),
                ttl: 20,
            },
            DnsRecord::A {
                domain: "new-fp-shed.wg1.b.yahoo.com".to_string(),
                addr: Ipv4Addr::new(202, 165, 107, 49),
                ttl: 20,
            },
        ];

        let pack = DnsPacket::builder()
            .header(header)
            .questions(vec![question])
            .answers(records)
            .build();

        let (_, result) = packet(&yahoo_packet(), &yahoo_packet()).unwrap();

        assert_eq!(pack, result);
    }

    #[test]
    fn dns_authorities_parsing_works() {
        env_logger::init();

        let pack_buf = [
            0x4, 0xd1, 0x81, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0xd, 0x0, 0xe, // header
            0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0,
            0x1, // question
            // authorities
            0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x14, 0x1, 0x61, 0xc, 0x67,
            0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x3, 0x6e, 0x65,
            0x74, 0x0, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x62,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x63,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x64,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x65,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x66,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x67,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x68,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x69,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x6a,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x6b,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x6c,
            0xc0, 0x2a, 0xc0, 0x13, 0x0, 0x2, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4, 0x1, 0x6d,
            0xc0, 0x2a, 0xc0, 0x28, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            // resources
            0xc0, 0x5, 0x6, 0x1e, 0xc0, 0x48, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x21, 0xe, 0x1e, 0xc0, 0x58, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x1a, 0x5c, 0x1e, 0xc0, 0x68, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x1f, 0x50, 0x1e, 0xc0, 0x78, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0xc, 0x5e, 0x1e, 0xc0, 0x88, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x23, 0x33, 0x1e, 0xc0, 0x98, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x2a, 0x5d, 0x1e, 0xc0, 0xa8, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x36, 0x70, 0x1e, 0xc0, 0xb8, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x2b, 0xac, 0x1e, 0xc0, 0xc8, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x30, 0x4f, 0x1e, 0xc0, 0xd8, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x34, 0xb2, 0x1e, 0xc0, 0xe8, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x29, 0xa2, 0x1e, 0xc0, 0xf8, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0, 0x4,
            0xc0, 0x37, 0x53, 0x1e, 0xc0, 0x28, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x2, 0xa3, 0x0, 0x0,
            0x10, 0x20, 0x1, 0x5, 0x3, 0xa8, 0x3e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0,
            0x30,
        ];

        let header = DnsHeader {
            id: 1233,
            recursion_desired: true,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: true,
            rescode: ResponseCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions: 1,
            answers: 0,
            authoritative_entries: 13,
            resource_entries: 14,
        };
        let question = DnsQuestion {
            name: "google.com".to_string(),
            qtype: QueryType::A,
        };
        let authoritative_records = vec![
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "a.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "b.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "c.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "d.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "e.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "f.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "g.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "h.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "i.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "j.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "k.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "l.gtld-servers.net".to_string(),
                ttl: 172800,
            },
            DnsRecord::NS {
                domain: "com".to_string(),
                host: "m.gtld-servers.net".to_string(),
                ttl: 172800,
            },
        ];

        let resource_records = vec![
            DnsRecord::A {
                domain: "a.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 5, 6, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "b.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 33, 14, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "c.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 26, 92, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "d.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 31, 80, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "e.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 12, 94, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "f.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 35, 51, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "g.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 42, 93, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "h.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 54, 112, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "i.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 43, 172, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "j.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 48, 79, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "k.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 52, 178, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "l.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 41, 162, 30),
                ttl: 172800,
            },
            DnsRecord::A {
                domain: "m.gtld-servers.net".to_string(),
                addr: Ipv4Addr::new(192, 55, 83, 30),
                ttl: 172800,
            },
            DnsRecord::AAAA {
                domain: "a.gtld-servers.net".to_string(),
                addr: "2001:503:a83e::2:30".parse::<Ipv6Addr>().unwrap(),
                ttl: 172800,
            },
        ];

        let pack = DnsPacket::builder()
            .header(header)
            .questions(vec![question])
            .authorities(authoritative_records)
            .resources(resource_records)
            .build();

        let (_, result) = packet(&pack_buf, &pack_buf).unwrap();

        assert_eq!(pack, result);
    }
}
