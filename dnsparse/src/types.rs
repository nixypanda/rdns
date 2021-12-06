use std::net::{Ipv4Addr, Ipv6Addr};
use typed_builder::TypedBuilder;

// All communications inside of the domain protocol are carried in a single
// format called a message.  The top level format of message is divided
// into 5 sections (some of which are empty in certain cases) shown below:
//
//     +---------------------+
//     |        Header       |
//     +---------------------+
//     |       Question      | the question for the name server
//     +---------------------+
//     |        Answer       | RRs answering the question
//     +---------------------+
//     |      Authority      | RRs pointing toward an authority
//     +---------------------+
//     |      Additional     | RRs holding additional information
//     +---------------------+
//
// The header section is always present.  The header includes fields that
// specify which of the remaining sections are present, and also specify
// whether the message is a query or a response, a standard query or some
// other opcode, etc.
#[derive(Clone, Debug, PartialEq, Eq, TypedBuilder)]
pub struct DnsPacket {
    pub header: DnsHeader,

    #[builder(default = vec![])]
    pub questions: Vec<DnsQuestion>,
    #[builder(default = vec![])]
    pub answers: Vec<DnsRecord>,
    #[builder(default = vec![])]
    pub authorities: Vec<DnsRecord>,
    #[builder(default = vec![])]
    pub resources: Vec<DnsRecord>,
}

// The header contains the following fields:
//                                  1  1  1  1  1  1
//    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      ID                       |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    QDCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ANCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    NSCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ARCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Clone, Debug, PartialEq, Eq, TypedBuilder)]
pub struct DnsHeader {
    // A random identifier is assigned to query packets. Response packets must reply with the same
    // id. This is needed to differentiate responses due to the stateless nature of UDP.
    pub id: u16,

    // 0 for queries, 1 for responses.
    #[builder(default = false)]
    pub response: bool,

    // A four bit field that specifies kind of query in this message.  This value is set by the
    // originator of a query and copied into the response.  The values are:
    // 0     a standard query (QUERY)
    // 1     an inverse query (IQUERY)
    // 2     a server status request (STATUS)
    // 3-15  reserved for future use
    #[builder(default = 0)]
    pub opcode: u8,
    // Authoritative Answer - this bit is valid in responses, and specifies that the responding
    // name server is an authority for the domain name in question section.
    #[builder(default = false)]
    pub authoritative_answer: bool,
    #[builder(default = false)]
    // TrunCation - specifies that this message was truncated due to length greater than that
    // permitted on the transmission channel.
    pub truncated_message: bool,
    // Recursion Desired - this bit may be set in a query and is copied into the response.  If RD
    // is set, it directs the name server to pursue the query recursively.  Recursive query support
    // is optional.
    #[builder(default = false)]
    pub recursion_desired: bool,

    // Recursion Available - this be is set or cleared in a response, and denotes whether recursive
    // query support is available in the name server.
    #[builder(default = false)]
    pub recursion_available: bool,
    #[builder(default = false)]
    // Originally reserved for later use, but now used for DNSSEC queries.
    pub z: bool,
    #[builder(default = false)]
    pub authed_data: bool,
    #[builder(default = false)]
    pub checking_disabled: bool,
    #[builder(default = ResponseCode::NOERROR)]
    pub rescode: ResponseCode, // 4 bits

    // The number of entries in the Question Section
    #[builder(default = 0)]
    pub questions: u16,
    // The number of entries in the Answer Section
    #[builder(default = 0)]
    pub answers: u16,
    // The number of entries in the Authority Section
    #[builder(default = 0)]
    pub authoritative_entries: u16,
    // The number of entries in the Additional Section
    #[builder(default = 0)]
    pub resource_entries: u16,
}

impl DnsHeader {
    pub fn flags(&self) -> u16 {
        (self.rescode as u16)
            | ((self.checking_disabled as u16) << 4)
            | ((self.authed_data as u16) << 5)
            | ((self.z as u16) << 6)
            | ((self.recursion_available as u16) << 7)
            | ((self.recursion_desired as u16) << 8)
            | ((self.truncated_message as u16) << 9)
            | ((self.authoritative_answer as u16) << 10)
            | ((self.opcode as u16) << 11)
            | ((self.response as u16) << 15)
    }
}

//  Response code - this 4 bit field is set as part of responses.  The values have the following
//  interpretation:
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseCode {
    // No error condition
    NOERROR = 0,
    // Format error - The name server was unable to interpret the query.
    FORMERR = 1,
    // Server failure - The name server was unable to process this query due to a problem with the
    // name server.
    SERVFAIL = 2,
    // Name Error - Meaningful only for responses from an authoritative name server, this code
    // signifies that the domain name referenced in the query does not exist.
    NXDOMAIN = 3,
    // Not Implemented - The name server does not support the requested kind of query.
    NOTIMP = 4,
    // Refused - The name server refuses to perform the specified operation for policy reasons.
    // For example, a name server may not wish to provide the information to the particular
    // requester, or a name server may not wish to perform a particular operation (e.g., zone
    // transfer) for particular data.
    REFUSED = 5,
    //  6-15  Reserved for future use.
}

impl ResponseCode {
    pub fn from_num(num: u8) -> ResponseCode {
        match num {
            1 => ResponseCode::FORMERR,
            2 => ResponseCode::SERVFAIL,
            3 => ResponseCode::NXDOMAIN,
            4 => ResponseCode::NOTIMP,
            5 => ResponseCode::REFUSED,
            _ => ResponseCode::NOERROR,
        }
    }
}

// The question section is used to carry the "question" in most queries, i.e., the parameters that
// define what is being asked.  The section contains QDCOUNT (usually 1) entries, each of the
// following format:
//                                  1  1  1  1  1  1
//    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                                               |
//  /                     QNAME                     /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                     QTYPE                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                     QCLASS                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    // The domain name, encoded as a sequence of labels as described below
    pub name: String,
    // The Record Type
    pub qtype: QueryType,
    // The class is almost always set to 1, so we will not represent it here
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    CNAME,
    NS,
    MX,
    AAAA,
}

impl QueryType {
    pub fn to_num(self) -> u16 {
        match self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::CNAME => 5,
            QueryType::NS => 2,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

// The answer, authority, and additional sections all share the same format: a variable number of
// resource records, where the number of records is specified in the corresponding count field in
// the header.  Each resource record has the following format:
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                                               /
//     /                      NAME                     /
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     CLASS                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TTL                      |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                   RDLENGTH                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//     /                     RDATA                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// | ID | Name  | Description                              | Encoding                                         |
// |----+-------+------------------------------------------+--------------------------------------------------|
// | 1  | A     | Alias - Mapping names to IP addresses    | Preamble + Four bytes for IPv4 adress            |
// | 2  | NS    | Name Server - The DNS server address     | Preamble + Label Sequence                        |
// | 5  | CNAME | Canonical Name - Maps names to names     | Preamble + Label Sequence                        |
// | 15 | MX    | Mail eXchange - mail server for a domain | Preamble + 2-bytes for priority + Label Sequence |
// | 28 | AAAA  | IPv6 alias                               | Premable + Sixteen bytes for IPv6 adress         |
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
}

impl DnsPacket {
    pub fn first_question(&self) -> Option<&DnsQuestion> {
        self.questions.get(0)
    }

    pub fn is_valid(&self) -> bool {
        self.header.rescode != ResponseCode::NOERROR
    }

    pub fn has_answers(&self) -> bool {
        !self.answers.is_empty()
    }

    pub fn rescode(&self) -> ResponseCode {
        self.header.rescode
    }

    pub fn qtype(&self) -> Option<QueryType> {
        self.first_question().map(|q| q.qtype)
    }

    pub fn qname(&self) -> Option<String> {
        self.first_question().map(|q| q.name.clone())
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|r| match r {
            DnsRecord::A { addr, .. } => Some(*addr),
            _ => None,
        })
    }

    fn get_ns(&self) -> impl Iterator<Item = (&str, &str)> {
        self.authorities.iter().filter_map(|record| match record {
            DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
            _ => None,
        })
    }

    fn get_ns_for<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.get_ns()
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns_for(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .cloned()
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns_for(qname).map(|(_, host)| host).next()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn get_resolved_ns_works() {
        let header = DnsHeader::builder().id(10).build();
        let question = DnsQuestion {
            name: "google.com".to_string(),
            qtype: QueryType::A,
        };
        let authoritative_records = vec![DnsRecord::NS {
            domain: "com".to_string(),
            host: "a.gtld-servers.net".to_string(),
            ttl: 172800,
        }];

        let resource_records = vec![DnsRecord::A {
            domain: "a.gtld-servers.net".to_string(),
            addr: Ipv4Addr::new(192, 5, 6, 30),
            ttl: 172800,
        }];

        let pack = DnsPacket::builder()
            .header(header)
            .questions(vec![question])
            .authorities(authoritative_records)
            .resources(resource_records)
            .build();

        let result = pack.get_resolved_ns("google.com");

        assert_eq!(Some(Ipv4Addr::new(192, 5, 6, 30)), result);
    }
}
