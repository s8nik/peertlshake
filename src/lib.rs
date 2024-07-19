#![warn(
    clippy::perf,
    clippy::semicolon_if_nothing_returned,
    clippy::missing_const_for_fn,
    clippy::use_self
)]

pub mod logger {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    pub fn init() -> anyhow::Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(EnvFilter::from_default_env())
            .try_init()?;

        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            tracing::error!("{info}");
            hook(info);
        }));

        Ok(())
    }
}
