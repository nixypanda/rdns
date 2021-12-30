use std::net::UdpSocket;

use log::info;

static DNS_SERVER: (&str, u16) = ("127.0.0.1", 2053);

fn main() -> anyhow::Result<()> {
    env_logger::init();

    info!("Starting DNS Server: {:?}", DNS_SERVER);
    let _socket = UdpSocket::bind(DNS_SERVER)?;

    // TODO: Write the DNS server

    Ok(())
}
