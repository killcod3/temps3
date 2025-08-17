use clap::Parser;
use log::info;

mod cli;
mod config;
mod core;
mod credentials;
mod error;
mod s3;
mod storage;

use cli::{Cli, Commands, CredentialAction, ManageAction};
use core::TempS3App;
use error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Load config first to get the log level
    let config = config::Config::load().await.unwrap_or_else(|_| config::Config::default());
    
    // Initialize logging with config file setting as default, but allow RUST_LOG override
    let default_log_level = &config.log_level;
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(default_log_level)
    ).init();

    let cli = Cli::parse();

    info!("TempS3 CLI starting...");

    let app = TempS3App::new().await?;

    match cli.command {
        Commands::Init => app.init().await?,
        Commands::Upload { file_path, ttl, verbose } => {
            app.upload(file_path, ttl, verbose).await?
        }
        Commands::List { ttl, status, limit, page, sort, order, search, verbose } => {
            app.list_with_options(ttl, status, limit, page, sort, order, search, verbose).await?
        }
        Commands::Config { check_credentials } => {
            app.config(check_credentials).await?
        }
        Commands::Credentials { action } => {
            match action {
                CredentialAction::Update { skip_validation } => {
                    app.update_credentials(skip_validation).await?
                }
                CredentialAction::Test => {
                    app.test_credentials().await?
                }
                CredentialAction::Remove { force } => {
                    app.remove_credentials(force).await?
                }
            }
        }
        Commands::Manage { action } => {
            match action {
                ManageAction::PurgeDatabase { force } => {
                    app.purge_database(force).await?
                }
                ManageAction::EmptyBucket { force } => {
                    app.empty_bucket(force).await?
                }
            }
        }
    }

    Ok(())
}
