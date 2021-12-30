# RDNS

The Domain Name System (DNS) is the hierarchical and decentralized naming
system used to identify computers, services, and other resources reachable
through the internet or other internet protocol networks.

The resource records contained in the DNS associate domain names with other
forms of information.  These are most commonly used to map human-friendly
domain names to the numerical IP addresses computers need to locate services
and devices using the underlying network protocols, but have been extended over
time to perform many other functions as well.

The Domain Name System has been an essential component of the functionality of
the Internet since 1985.

This is a toy clone of of DNS Server and Client.

## Note

I followed [this brillient guide](https://github.com/EmilHernvall/dnsguide) to
make this. Though have taken some steps differnently.

Most important of those was separating out the parsing stuff into a separate
workspace crate.

### Why?

Segregation of the protocol pieces from the parsing stuff.

If someone wants to just see how dns works and does not wish to delve into the
details of how to do parsing and writing into the packet format and just use
that part of the crate and work on their implementation.

With this someone can follow the aforementioned guide whilst skiping over all
the parsing/bit-fiddling stuff

Note: There are some helpers provided in addition to basic parsing and writing.
But one can easily ignore these and just write thir own

It is highly recommended that one reads through the `dnsparse/src/types.rs`
file. Just reading through the comments should be enough

For the rest of this text we will assume that the types/parsing/writing packet
stuff is in place and just focus on the steps taken by the actual protocol as
outlined in the initial RFC

## Client: Theory

The client will call a pre-existing DNS Server with the query packet and will
parse it's response and will show it to the user. With that info the steps that
we are required to perform and fairly straightforward

## Client: High Level Flow
- Get the query from the user
- Construct a `DnsPacket` from this query
- Send the packet to any DNS server
- Receive the response packet
- Parse this packet
- Show the response to the user

[Implementation](./src/bin/client.rs)

## Client: Execution
`cargo run --bin client -- --query yahoo.com`

## Server: Theory
The DNS system contains the following components

**Root name servers**
- Official, contact-of-last-resort by name servers when unable to service a
  request 
- Incredibly important (Internet won't work if they go down kinda important)
- ICANN manages root DNS domains
- There are 13 logical root servers which are replicated hundreds of times 
    - Why 13?
 
**Top-Level Domain Servers**
- Top level names (e.g. .edu, .com, etc) 
- Registered and maintained by ICANN 
- TLDs are given to countries (ISO 3166 international 2-character country code) 
- TLDs don't have mappings but can redirect to Authoritative namer servers 

**Authoritative DNS servers**
- Org's own DNS server, providing authoritative hostname to IP mappings for
  orgs named hosts 
- Can be maintained by organization or service provider 
- ANS stores a table of domain name to IP addresses 

**Local DNS servers**
- When host makes a query, it is sent to its local DNS server 
- If we don't get it here (i.e. in cache) then we start the DNS resolution
  process


### The Name Resolution Process

- User Program looks up it's own cache 
    - If it finds it there great otherwise the following steps are followed 
- The request then goes to the **Resolver server**
    - Each host has this configured (to view `scutil --dns`) 
    - Finds it in the cache great otherwise onwards 
- The resolver then goes to the Root server.
    - One can simulate this by executing `dig +norecurse @198.41.0.4 www.google.com`
    - You can get a list of other Root server addresses from
      [named.root](https://www.internic.net/domain/named.root)
- The Root server does not have the resolution but it will reply with the list
  of ip address for this TLD 
    - E.g. if I am looking up goole.com then it will be forwarded to `.com` TLD 
- The resolver then goes to the TLD DNS server (whose ip we got in last step) 
    - One can simulate this step by executing `dig +norecurse @192.5.6.30 www.google.com`
    - Where `192.4.5.30` was in the response of the previous `dig` command that
      we executed
- The TLD server returns a list of ips for Authoritative Name servers 
- The resolver then goes to the Authoritative Name Server 
    - Once can simulate this step by executing `dig +norecurse @216.239.32.10 www.google.com`
- ANS responds with an IP from it's database 
    - It chooses one of those IP addresses and gives it to you 
- **Resolver** stores this in it's cache and returns the value to the
  requesting host 
- Requesting host stores this info in it's cache

Armed with this knowledge we can easily come up with an [implementation](./src/main.rs)

## Server: Execution

1. Start the server: `RUST_LOG=<log_level> cargo run --bin rdns`
2. Use a client to contact the server: `dig @127.0.0.1 -p 2053 www.google.com`


## How do I write my own?

You can checkout the branch `my-own` which only has the `dnsparse` workspace
crate and the basic folder structure in place. So you can just checkout that
branch and start writing your own version, without delving into the packet
parsing and writing packet buffers.

Happy learning!
