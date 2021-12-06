pub use dnsparse::{write_packet, DnsHeader, DnsPacket, DnsQuestion, QueryType, ResponseCode};
use log::{debug, error, info, warn};
use std::{
    convert::TryFrom,
    net::{Ipv4Addr, UdpSocket},
};

pub const MAX_PACKET_SIZE: usize = 512;
pub const ROOT_DNS_SERVER: (Ipv4Addr, u16) = (Ipv4Addr::new(198, 41, 0, 4), 53);
pub const RECURSIVE_DNS_SERVER: (Ipv4Addr, u16) = (Ipv4Addr::new(8, 8, 8, 8), 53);

pub fn resolve(request: DnsPacket) -> anyhow::Result<DnsPacket> {
    let base_header_builder = DnsHeader::builder()
        .id(request.header.id)
        .recursion_desired(true)
        .recursion_available(true)
        .response(true);

    let response = if let Some(question) = request.first_question() {
        let (qname, qtype) = (request.qname().unwrap(), request.qtype().unwrap());
        info!("Starting recursive lookup for {} ({:?})", qname, qtype);

        match recursive_lookup(&qname, qtype) {
            Ok(result) => {
                let header = base_header_builder
                    .questions(1)
                    .answers(result.answers.len() as u16)
                    .authoritative_entries(result.authorities.len() as u16)
                    .resource_entries(result.resources.len() as u16)
                    .build();
                DnsPacket::builder()
                    .header(header)
                    .questions(vec![question.clone()])
                    .answers(result.answers)
                    .authorities(result.authorities)
                    .resources(result.resources)
                    .build()
            }
            Err(error) => {
                let header = base_header_builder.rescode(ResponseCode::SERVFAIL).build();
                let response = DnsPacket::builder().header(header).build();
                error!("Server failure: {:?}", error);
                response
            }
        }
    } else {
        let header = base_header_builder.rescode(ResponseCode::FORMERR).build();
        let response = DnsPacket::builder().header(header).build();
        error!("Client provided insufficient info: {:#?}", response);
        response
    };

    Ok(response)
}

pub fn recursive_lookup(qname: &str, qtype: QueryType) -> anyhow::Result<DnsPacket> {
    let mut ns = ROOT_DNS_SERVER;
    loop {
        info!(
            "attempting lookup of {} ({:?}) with ns {:?}",
            qname, qtype, ns
        );

        let ns_copy = ns;
        let response = lookup(qname, qtype, ns_copy)?;

        if response.has_answers() && response.rescode() == ResponseCode::NOERROR {
            info!("Found entries without any errors {:?}", response);
            return Ok(response);
        }

        if response.rescode() == ResponseCode::NXDOMAIN {
            warn!(
                "Authoritative servers {:?} says name {} ({:?}) does not exist",
                ns, qname, qtype
            );
            return Ok(response);
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = (new_ns, 53);
            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => {
                warn!("No NS Record exist: {:#?}", response);
                return Ok(response);
            }
        };

        info!("Need to resolve IP for server",);
        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = (new_ns, 53);
        } else {
            return Ok(response);
        }
    }
}

pub fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> anyhow::Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let random_id = rand::random();
    let request = mk_query(random_id, qname, qtype);
    debug!("Request: {:?}", request);

    let mut req_buffer = vec![0u8; MAX_PACKET_SIZE];
    let size = write_packet(&mut req_buffer, &request)?;

    socket.send_to(&req_buffer[..size], server)?;

    let mut response_buffer = vec![0u8; MAX_PACKET_SIZE];
    let (size, _src) = socket.recv_from(&mut response_buffer)?;
    let response = DnsPacket::try_from(&response_buffer[..size]).map_err(anyhow::Error::msg)?;
    debug!("Response: {:?}", response);

    Ok(response)
}

fn mk_query(id: u16, qname: &str, qtype: QueryType) -> DnsPacket {
    let header = DnsHeader::builder()
        .id(id)
        .questions(1)
        .recursion_desired(true)
        .build();

    let question = DnsQuestion {
        name: qname.to_string(),
        qtype,
    };

    DnsPacket::builder()
        .header(header)
        .questions(vec![question])
        .build()
}
