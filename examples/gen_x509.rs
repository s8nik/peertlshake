use std::{
    io::Write,
    path::{Path, PathBuf},
};

use chrono::Datelike;
use clap::Parser;
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, DnValue, IsCa, KeyPair,
    PrintableString,
};
use rsa::{pkcs1::LineEnding, pkcs8::EncodePrivateKey, RsaPrivateKey};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    output_path: String,

    #[arg(long, default_value = "Poland")]
    country_name: String,

    #[arg(long, default_value = "s8nik")]
    organization_name: String,
}

fn key_pair() -> anyhow::Result<KeyPair> {
    let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
    let key = private_key.to_pkcs8_pem(LineEnding::CRLF)?;
    KeyPair::from_pem(&key).map_err(|e| anyhow::anyhow!(e))
}

fn cert_params(country_name: &str, organization_name: &str) -> anyhow::Result<CertificateParams> {
    let mut params = CertificateParams::default();

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    params.distinguished_name.push(
        DnType::CountryName,
        DnValue::PrintableString(PrintableString::try_from(country_name)?),
    );

    params
        .distinguished_name
        .push(DnType::OrganizationName, organization_name);

    let now = chrono::Local::now();
    params.not_before = date_time_ymd(now.year(), now.month() as _, now.day() as _);
    params.not_after = date_time_ymd(now.year() + 1, now.month() as _, now.day() as _);

    Ok(params)
}

fn write_pem(pem: String, filepath: impl AsRef<Path>) -> anyhow::Result<()> {
    let mut file = std::fs::File::create(filepath)?;

    file.write_all(pem.as_bytes())?;
    file.flush()?;
    file.sync_all()?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let output_path = Path::new(&args.output_path);

    anyhow::ensure!(output_path.exists(), "output dir path should exist");
    anyhow::ensure!(output_path.is_dir(), "output path should be a dir");

    tracing::info!("generate cert & key...");

    let cert_params = cert_params(&args.country_name, &args.organization_name)?;
    let key_pair = key_pair()?;

    write_pem(
        key_pair.serialize_pem(),
        [&args.output_path, "client.key"]
            .iter()
            .collect::<PathBuf>(),
    )?;

    write_pem(
        cert_params.self_signed(&key_pair)?.pem(),
        [&args.output_path, "client.cert"]
            .iter()
            .collect::<PathBuf>(),
    )?;

    tracing::info!("done!");

    Ok(())
}
