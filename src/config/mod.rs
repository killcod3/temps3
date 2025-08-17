use crate::error::Result;
use dirs::config_dir;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub aws_region: String,
    pub bucket_name: String,
    pub presigned_url_expiry_days: u32,
    pub max_concurrent_uploads: u32,
    pub max_retries: u32,
    pub base_retry_delay_ms: u64,
    pub database_path: PathBuf,
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            aws_region: "us-east-1".to_string(),
            bucket_name: generate_unique_bucket_name(),
            presigned_url_expiry_days: 7,
            max_concurrent_uploads: 10,
            max_retries: 3,
            base_retry_delay_ms: 1000,
            database_path: get_config_dir().join("temps3.db"),
            log_level: "warn".to_string(),
        }
    }
}

impl Config {
    pub async fn load() -> Result<Self> {
        let config_path = get_config_path();
        
        if config_path.exists() {
            let content = fs::read_to_string(&config_path).await?;
            let config: Config = serde_yaml::from_str(&content)?;
            config.validate()?;
            Ok(config)
        } else {
            let config = Config::default();
            config.save().await?;
            Ok(config)
        }
    }

    pub async fn save(&self) -> Result<()> {
        let config_dir = get_config_dir();
        fs::create_dir_all(&config_dir).await?;
        
        let config_path = get_config_path();
        let content = serde_yaml::to_string(self)?;
        fs::write(config_path, content).await?;
        
        Ok(())
    }

    /// Validate all configuration values
    fn validate(&self) -> Result<()> {
        self.validate_presigned_url_expiry()?;
        Ok(())
    }

    /// Validate presigned URL expiry days (AWS S3 limit is 7 days maximum)
    fn validate_presigned_url_expiry(&self) -> Result<()> {
        if self.presigned_url_expiry_days == 0 {
            return Err(crate::error::TempS3Error::ValidationError(
                "Presigned URL expiry must be at least 1 day".to_string()
            ));
        }
        if self.presigned_url_expiry_days > 7 {
            return Err(crate::error::TempS3Error::ValidationError(
                format!(
                    "Presigned URL expiry cannot exceed 7 days (AWS S3 limit). Current value: {} days. Please update your config file at: {}",
                    self.presigned_url_expiry_days,
                    get_config_path().display()
                )
            ));
        }
        Ok(())
    }

    /// Update bucket name and save configuration
    #[allow(dead_code)]
    pub async fn update_bucket_name(&mut self, new_bucket_name: String) -> Result<()> {
        self.bucket_name = new_bucket_name;
        self.save().await
    }
}

pub fn get_config_dir() -> PathBuf {
    let config_dir = config_dir()
        .unwrap_or_else(|| {
            // Fallback to current directory if config_dir is not available
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        })
        .join("temps3");
    
    // If we can't create the directory, fall back to current directory
    if let Err(_) = std::fs::create_dir_all(&config_dir) {
        PathBuf::from(".temps3")
    } else {
        config_dir
    }
}

pub fn get_config_path() -> PathBuf {
    get_config_dir().join("config.yml")
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppState {
    pub initialized: bool,
    pub last_bucket_check: Option<chrono::DateTime<chrono::Utc>>,
    pub credentials_validated: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            initialized: false,
            last_bucket_check: None,
            credentials_validated: false,
        }
    }
}

impl AppState {
    pub async fn load() -> Result<Self> {
        let state_path = get_config_dir().join("state.yml");
        
        if state_path.exists() {
            let content = fs::read_to_string(&state_path).await?;
            let state: AppState = serde_yaml::from_str(&content)?;
            Ok(state)
        } else {
            Ok(AppState::default())
        }
    }

    pub async fn save(&self) -> Result<()> {
        let config_dir = get_config_dir();
        fs::create_dir_all(&config_dir).await?;
        
        let state_path = get_config_dir().join("state.yml");
        let content = serde_yaml::to_string(self)?;
        fs::write(state_path, content).await?;
        
        Ok(())
    }
}

/// Generate a unique bucket name to avoid global collisions
pub fn generate_unique_bucket_name() -> String {
    let uuid = Uuid::new_v4().to_string().replace('-', "")[..8].to_string();
    format!("temps3-{}", uuid)
}

/// Validate bucket name according to AWS S3 rules
pub fn validate_bucket_name(name: &str) -> std::result::Result<(), String> {
    // AWS S3 bucket naming rules
    if name.len() < 3 || name.len() > 63 {
        return Err("Bucket name must be between 3 and 63 characters long".to_string());
    }
    
    if !name.chars().next().unwrap_or('a').is_ascii_lowercase() {
        return Err("Bucket name must start with a lowercase letter".to_string());
    }
    
    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.') {
        return Err("Bucket name can only contain lowercase letters, numbers, hyphens, and periods".to_string());
    }
    
    if name.contains("..") || name.starts_with('-') || name.ends_with('-') {
        return Err("Bucket name cannot contain consecutive periods or start/end with hyphens".to_string());
    }
    
    // Check if it looks like an IP address
    if name.split('.').all(|part| part.parse::<u8>().is_ok()) && name.split('.').count() == 4 {
        return Err("Bucket name cannot be formatted as an IP address".to_string());
    }
    
    Ok(())
}
