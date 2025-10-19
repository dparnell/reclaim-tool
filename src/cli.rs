use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(ValueEnum, Clone, Debug)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Fetch a new private key and certificate and save them to the config directory
    FetchCerts,

    /// Subscribe to dontek{hexid}/status/psw and print incoming messages
    Subscribe {
        /// The 17-digit unique decimal ID of the Reclaim Energy unit
        #[arg(long, value_name = "DECIMAL_ID")] 
        unique_id: String,
    },
}

#[derive(Parser, Debug)]
#[command(name = "reclaim", version, about = "AWS IoT client for Reclaim Energy heat pump controller")] 
pub struct Cli {
    /// AWS region (e.g. ap-southeast-2)
    #[arg(long, global = true, default_value = crate::reclaim::DEFAULT_AWS_REGION)]
    pub region: String,

    /// AWS IoT ATS endpoint hostname
    #[arg(long, global = true, default_value = crate::reclaim::DEFAULT_AWS_ENDPOINT)]
    pub endpoint: String,

    /// Cognito Identity Pool ID
    #[arg(long, global = true, default_value = crate::reclaim::DEFAULT_AWS_IDENTITY_POOL)]
    pub identity_pool_id: String,

    /// Configuration directory (defaults to ~/.config/reclaim)
    #[arg(long, global = true)]
    pub config_dir: Option<PathBuf>,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, global = true, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Refresh interval in seconds for periodic read command
    #[arg(long, global = true, default_value_t = 60)]
    pub refresh_interval: u64,

    #[command(subcommand)]
    pub command: Commands,
}

pub fn parse() -> Cli {
    Cli::parse()
}

pub fn init_logging(level: &LogLevel) {
    let level_str = match level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::new(level_str);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(true)
        .with_target(false)
        .with_level(true)
        .compact()
        .init();
}
