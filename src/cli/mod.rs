use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "temps3",
    about = "A CLI application for temporary file storage using AWS S3 with automatic expiration",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize credentials and bucket configuration
    Init,
    
    /// Upload a file to S3 with TTL
    Upload {
        /// Path to the file to upload
        file_path: PathBuf,
        
        /// Time-to-live for the file (1d, 3d, or 5d)
        #[arg(long, default_value = "1d", value_parser = parse_ttl)]
        ttl: TtlDuration,
        
        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// List previous uploads
    List {
        /// Filter by TTL duration (1d, 3d, 5d)
        #[arg(long)]
        ttl: Option<String>,
        
        /// Filter by status (active, expired, all)
        #[arg(long, default_value = "all")]
        status: String,
        
        /// Number of results per page
        #[arg(long, default_value = "10")]
        limit: u32,
        
        /// Page number (starting from 1)
        #[arg(long, default_value = "1")]
        page: u32,
        
        /// Sort by (date, size, name, expiry)
        #[arg(long, default_value = "date")]
        sort: String,
        
        /// Sort order (asc, desc)
        #[arg(long, default_value = "desc")]
        order: String,
        
        /// Search pattern in file names
        #[arg(long)]
        search: Option<String>,
        
        /// Show detailed information for each upload
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Manage configuration
    Config {
        /// Check credential validity and permissions
        #[arg(long)]
        check_credentials: bool,
    },
    
    /// Credential management operations
    Credentials {
        #[command(subcommand)]
        action: CredentialAction,
    },
    
    /// Database and bucket management operations
    Manage {
        #[command(subcommand)]
        action: ManageAction,
    },
}

#[derive(Subcommand)]
pub enum CredentialAction {
    /// Update AWS credentials
    Update {
        /// Skip validation of new credentials
        #[arg(long)]
        skip_validation: bool,
    },
    
    /// Test current credentials and show status
    Test,
    
    /// Remove stored credentials
    Remove {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum ManageAction {
    /// Purge all entries from the local database
    PurgeDatabase {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    
    /// Empty the S3 bucket and mark all local entries as expired
    EmptyBucket {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Clone)]
pub enum TtlDuration {
    OneDay,
    ThreeDays,
    FiveDays,
}

impl TtlDuration {
    pub fn as_tag(&self) -> &'static str {
        match self {
            TtlDuration::OneDay => "1d",
            TtlDuration::ThreeDays => "3d",
            TtlDuration::FiveDays => "5d",
        }
    }

    pub fn as_days(&self) -> i32 {
        match self {
            TtlDuration::OneDay => 1,
            TtlDuration::ThreeDays => 3,
            TtlDuration::FiveDays => 5,
        }
    }
}

fn parse_ttl(s: &str) -> Result<TtlDuration, String> {
    match s {
        "1d" => Ok(TtlDuration::OneDay),
        "3d" => Ok(TtlDuration::ThreeDays),
        "5d" => Ok(TtlDuration::FiveDays),
        _ => Err(format!("Invalid TTL '{}'. Valid options: 1d, 3d, 5d", s)),
    }
}
