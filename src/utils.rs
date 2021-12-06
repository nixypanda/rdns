use std::{convert::TryFrom, fs::File, io::Read};

use crate::{types::DnsPacket, writer::write as write_packet};

fn _parse_packet_from_file(filename: &str) -> anyhow::Result<DnsPacket> {
    // read
    let mut f = File::open(filename)?;
    let mut vec = Vec::new();
    f.read_to_end(&mut vec)?;

    let packet = DnsPacket::try_from(&vec[..]).map_err(anyhow::Error::msg)?;
    println!("Read: {:x?}", &vec);

    Ok(packet)
}

fn _write_dns_packet(packet: &DnsPacket) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 512];
    let size = write_packet(&mut buf, packet)?;
    println!("Write: {:x?}", &buf[..size]);

    Ok(())
}
