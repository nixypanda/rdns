mod parser;
mod types;
mod utils;
mod writer;

pub use types::{DnsHeader, DnsPacket, DnsQuestion, QueryType, ResultCode};

pub use parser::packet as dns_packet_parser;
pub use writer::write as write_packet;
