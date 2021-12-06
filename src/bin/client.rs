use log::debug;
use std::{convert::TryFrom, net::UdpSocket};
use structopt::StructOpt;

use rdns::{write_packet, DnsHeader, DnsPacket, DnsQuestion, QueryType, MAX_PACKET_SIZE};

static RESOLVER_SERVER: (&str, u16) = ("8.8.8.8", 53);
static UDP_RESPONSE_LISTENER: (&str, u16) = ("0.0.0.0", 2053);

fn mk_query(qname: &str, qtype: QueryType) -> DnsPacket {
    let header = DnsHeader::builder()
        .id(818) // This should be a random number
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

#[derive(Debug, StructOpt)]
#[structopt(name = "DNS Client", about = "Search DNS records for a given query")]
struct Opt {
    #[structopt(short, long, default_value = "google.com")]
    query: String,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    debug!("parsing args");

    let Opt { query } = StructOpt::from_args();
    debug!("args {}", query);

    let socket = UdpSocket::bind(UDP_RESPONSE_LISTENER)?;

    let request = mk_query(&query, QueryType::A);
    debug!("Request: {:#?}", request);

    let mut req_buffer = vec![0u8; MAX_PACKET_SIZE];
    let size = write_packet(&mut req_buffer, &request)?;

    socket.send_to(&req_buffer[..size], RESOLVER_SERVER)?;

    let mut response_buffer = vec![0u8; MAX_PACKET_SIZE];
    let (size, _src) = socket.recv_from(&mut response_buffer)?;

    let response = DnsPacket::try_from(&response_buffer[..size]).map_err(anyhow::Error::msg)?;

    print_packet(&response);

    Ok(())
}

pub fn print_packet(packet: &DnsPacket) {
    println!("{:#?}", packet.header);

    for q in &packet.questions {
        println!("{:#?}", q);
    }
    for rec in &packet.answers {
        println!("{:#?}", rec);
    }
    for rec in &packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in &packet.resources {
        println!("{:#?}", rec);
    }
}
