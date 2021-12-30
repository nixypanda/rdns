use log::debug;
use structopt::StructOpt;

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

    // TODO: Write DNS client

    Ok(())
}
