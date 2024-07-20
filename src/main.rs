use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Some(addr) = std::env::args().nth(1) else {
        eprintln!(r"Usage ./peertlshake <ip:port>");
        std::process::exit(1);
    };

    dotenv::dotenv()?;
    peertlshake::logger::init()?;

    let addr = std::net::SocketAddr::from_str(&addr)?;
    let x509 = peertlshake::X509::from_env().await?;
    let node = peertlshake::TlsNode::new(x509)?;

    // handshake
    node.connect_with_handshake(addr).await?;

    Ok(())
}
