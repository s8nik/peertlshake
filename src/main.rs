fn main() -> anyhow::Result<()> {
    dotenv::dotenv()?;
    peertlshake::logger::init()?;

    Ok(())
}
