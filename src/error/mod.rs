use thiserror::Error;

#[derive(Error, Debug)]
pub enum TempS3Error {
    #[error("AWS S3 error: {}", Self::get_detailed_s3_error_message(.0))]
    S3Error(aws_sdk_s3::Error),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Credential error: {0}")]
    CredentialError(String),

    #[error("Invalid AWS credentials: {0}")]
    InvalidCredentials(String),

    #[error("Expired AWS credentials: {0}")]
    ExpiredCredentials(String),

    #[error("Insufficient AWS permissions: {0}")]
    InsufficientPermissions(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Upload error: {0}")]
    UploadError(String),

    #[error("S3 lifecycle rule creation error: {0}")]
    LifecycleRuleError(String),

    #[error("Keyring error: {0}")]
    KeyringError(#[from] keyring::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type Result<T> = std::result::Result<T, TempS3Error>;

impl TempS3Error {

    /// Analyze AWS S3 error and convert to more specific credential error
    pub fn from_s3_error(error: aws_sdk_s3::Error) -> Self {
        let error_message = error.to_string().to_lowercase();
        
        if error_message.contains("invalidaccesskeyid") || error_message.contains("access key") {
            TempS3Error::InvalidCredentials("Your AWS Access Key ID is invalid or does not exist".to_string())
        } else if error_message.contains("signaturedoesnotmatch") || error_message.contains("signature") {
            TempS3Error::InvalidCredentials("Your AWS Secret Access Key is incorrect".to_string())
        } else if error_message.contains("tokenrefresh") || error_message.contains("expired") {
            TempS3Error::ExpiredCredentials("Your AWS session token has expired".to_string())
        } else if error_message.contains("access denied") || error_message.contains("forbidden") {
            TempS3Error::InsufficientPermissions("Your AWS credentials lack the required S3 permissions".to_string())
        } else {
            TempS3Error::S3Error(error)
        }
    }

    /// Get detailed S3 error information for better debugging
    pub fn get_detailed_s3_error_message(error: &aws_sdk_s3::Error) -> String {
        // AWS SDK error handling - check for specific error types
        let error_str = error.to_string();
        let lower_error = error_str.to_lowercase();
        
        // Check for specific AWS error patterns
        if lower_error.contains("throttling") || lower_error.contains("slow down") {
            "Rate limiting - S3 is throttling requests due to high volume".to_string()
        } else if lower_error.contains("internal error") || lower_error.contains("internalerror") {
            "S3 internal server error - temporary AWS issue".to_string()
        } else if lower_error.contains("service unavailable") || lower_error.contains("serviceunavailable") {
            "S3 service temporarily unavailable".to_string()
        } else if lower_error.contains("timeout") || lower_error.contains("timed out") {
            "Network timeout - connection to S3 timed out".to_string()
        } else if lower_error.contains("connection") || lower_error.contains("connect") {
            "Connection error - unable to establish connection to S3".to_string()
        } else if lower_error.contains("dns") {
            "DNS resolution error - unable to resolve S3 endpoint".to_string()
        } else if lower_error.contains("ssl") || lower_error.contains("tls") {
            "SSL/TLS error - secure connection failed".to_string()
        } else if lower_error.contains("access denied") || lower_error.contains("forbidden") {
            "Access denied - check AWS credentials and permissions".to_string()
        } else if lower_error.contains("no such bucket") {
            "Bucket not found - bucket may not exist or be in a different region".to_string()
        } else if lower_error.contains("invalid request") {
            "Invalid request - malformed request parameters".to_string()
        } else if lower_error.contains("token") && lower_error.contains("expired") {
            "AWS credentials expired - refresh your session token".to_string()
        } else {
            // Fallback for unknown errors - show the original message but clean it up
            if error_str.len() > 100 {
                format!("S3 Error: {}", &error_str[..97].trim_end())
            } else {
                format!("S3 Error: {}", error_str)
            }
        }
    }

    /// Get user-friendly error message with recovery suggestions
    pub fn user_friendly_message(&self) -> String {
        match self {
            TempS3Error::InvalidCredentials(msg) => {
                format!("❌ {}\n💡 Run 'temps3 init' to update your AWS credentials", msg)
            }
            TempS3Error::ExpiredCredentials(msg) => {
                format!("❌ {}\n💡 Run 'temps3 init' to refresh your AWS credentials", msg)
            }
            TempS3Error::InsufficientPermissions(msg) => {
                format!("❌ {}\n💡 Ensure your AWS user has S3 permissions (s3:GetObject, s3:PutObject, s3:CreateBucket, etc.)", msg)
            }
            TempS3Error::CredentialError(msg) => {
                format!("❌ Credential error: {}\n💡 Run 'temps3 init' to set up your AWS credentials", msg)
            }
            _ => self.to_string()
        }
    }
}

#[derive(Debug)]
pub struct RetryManager {
    max_retries: u32,
    base_delay_ms: u64,
}

impl RetryManager {
    pub fn new(max_retries: u32, base_delay_ms: u64) -> Self {
        Self {
            max_retries,
            base_delay_ms,
        }
    }

    pub async fn retry_with_backoff<F, Fut, T, E>(&self, mut operation: F) -> std::result::Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, E>>,
        E: std::fmt::Display,
    {
        let mut attempts = 0;
        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    attempts += 1;
                    if attempts > self.max_retries {
                        return Err(error);
                    }

                    let delay = self.base_delay_ms * 2_u64.pow(attempts - 1);
                    log::warn!(
                        "Operation failed (attempt {}/{}): {}. Retrying in {}ms...",
                        attempts,
                        self.max_retries,
                        error,
                        delay
                    );

                    tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                }
            }
        }
    }
}
