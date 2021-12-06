use std::{convert::TryFrom, net::UdpSocket};

use log::{debug, info};
use rdns::{resolve, write_packet, DnsPacket, MAX_PACKET_SIZE};

static DNS_SERVER: (&str, u16) = ("127.0.0.1", 2053);

fn main() -> anyhow::Result<()> {
    env_logger::init();

    info!("Starting DNS Server: {:?}", DNS_SERVER);
    let socket = UdpSocket::bind(DNS_SERVER)?;

    loop {
        let mut request_buffer = vec![0u8; MAX_PACKET_SIZE];
        let (size, source) = socket.recv_from(&mut request_buffer)?;

        let request = DnsPacket::try_from(&request_buffer[..size]).map_err(anyhow::Error::msg)?;
        debug!("Request: {:?}, from: {:?}", request, source);

        let response = resolve(request)?;
        debug!("Response: {:?}", response);

        let mut response_buffer = vec![0u8; MAX_PACKET_SIZE];
        let size = write_packet(&mut response_buffer, &response)?;
        socket.send_to(&response_buffer[..size], source)?;
    }
}
