use crate::error::{Result, TempS3Error};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::{Client as S3Client, primitives::ByteStream};
use base64::{engine::general_purpose, Engine as _};
use keyring::Entry;
use log::{debug, info, warn};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const SERVICE_NAME: &str = "temps3";
const CREDENTIALS_KEY: &str = "aws_credentials";
const ENCRYPTION_KEY: &str = "encryption_key";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: String,
}

#[derive(Debug)]
pub struct CredentialStatus {
    pub valid: bool,
    pub can_access_bucket: bool,
    pub has_required_permissions: bool,
    pub error_message: Option<String>,
    pub suggestion: Option<String>,
}

pub struct CredentialManager {
    keyring_entry: Option<Entry>,
    encryption_entry: Option<Entry>,
    config_dir: PathBuf,
    use_file_storage: bool,
}

impl CredentialManager {
    pub fn new() -> Result<Self> {
        let config_dir = crate::config::get_config_dir();
        
        // Try to create keyring entries, but fall back to file storage if it fails
        let (keyring_entry, encryption_entry, use_file_storage) = match (
            Entry::new(SERVICE_NAME, CREDENTIALS_KEY),
            Entry::new(SERVICE_NAME, ENCRYPTION_KEY),
        ) {
            (Ok(cred_entry), Ok(enc_entry)) => {
                // Test if keyring is actually available by trying a simple operation
                match cred_entry.get_password() {
                    Ok(_) | Err(keyring::Error::NoEntry) => {
                        info!("Using system keyring for credential storage");
                        (Some(cred_entry), Some(enc_entry), false)
                    }
                    Err(e) => {
                        warn!("Keyring test failed ({}), falling back to file storage", e);
                        (None, None, true)
                    }
                }
            }
            (Err(e1), _) | (_, Err(e1)) => {
                warn!("Failed to create keyring entries ({}), using file storage", e1);
                (None, None, true)
            }
        };

        if use_file_storage {
            info!("Using encrypted file storage for credentials");
        }

        Ok(Self {
            keyring_entry,
            encryption_entry,
            config_dir,
            use_file_storage,
        })
    }

    pub async fn store_credentials(&self, credentials: &AwsCredentials) -> Result<()> {
        info!("Storing AWS credentials securely");

        // Get or create encryption key
        let encryption_key = self.get_or_create_encryption_key()?;

        // Serialize and encrypt credentials
        let serialized = serde_json::to_string(credentials)?;
        let encrypted = self.encrypt_data(&serialized, &encryption_key)?;
        let encoded = general_purpose::STANDARD.encode(encrypted);

        if self.use_file_storage {
            // Store in encrypted file
            let creds_path = self.config_dir.join("credentials.enc");
            fs::write(&creds_path, encoded)
                .map_err(|e| TempS3Error::CredentialError(format!("Failed to store credentials to file: {}", e)))?;
        } else {
            // Store in keyring
            if let Some(ref entry) = self.keyring_entry {
                entry.set_password(&encoded)
                    .map_err(|e| TempS3Error::CredentialError(format!("Failed to store credentials: {}", e)))?;
            } else {
                return Err(TempS3Error::CredentialError("Keyring entry not available".to_string()));
            }
        }

        info!("Credentials stored successfully");
        Ok(())
    }

    pub async fn load_credentials(&self) -> Result<Option<AwsCredentials>> {
        debug!("Loading AWS credentials");

        let encoded = if self.use_file_storage {
            // Load from encrypted file
            let creds_path = self.config_dir.join("credentials.enc");
            match fs::read_to_string(&creds_path) {
                Ok(content) => content,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!("No stored credentials file found");
                    return Ok(None);
                }
                Err(e) => return Err(TempS3Error::CredentialError(format!("Failed to read credentials file: {}", e))),
            }
        } else {
            // Load from keyring
            if let Some(ref entry) = self.keyring_entry {
                match entry.get_password() {
                    Ok(content) => content,
                    Err(keyring::Error::NoEntry) => {
                        debug!("No stored credentials found in keyring");
                        return Ok(None);
                    }
                    Err(e) => return Err(TempS3Error::CredentialError(format!("Failed to load credentials: {}", e))),
                }
            } else {
                return Err(TempS3Error::CredentialError("Keyring entry not available".to_string()));
            }
        };

        let encryption_key = self.get_encryption_key()?;
        let encrypted = general_purpose::STANDARD.decode(encoded)
            .map_err(|e| TempS3Error::CredentialError(format!("Failed to decode credentials: {}", e)))?;
        
        let decrypted = self.decrypt_data(&encrypted, &encryption_key)?;
        let credentials: AwsCredentials = serde_json::from_str(&decrypted)?;
        
        debug!("Credentials loaded successfully");
        Ok(Some(credentials))
    }

    pub async fn delete_credentials(&self) -> Result<()> {
        info!("Deleting stored credentials");
        
        if self.use_file_storage {
            // Delete encrypted file
            let creds_path = self.config_dir.join("credentials.enc");
            if creds_path.exists() {
                fs::remove_file(&creds_path)
                    .map_err(|e| TempS3Error::CredentialError(format!("Failed to delete credentials file: {}", e)))?;
            }
        } else {
            // Delete from keyring
            if let Some(ref entry) = self.keyring_entry {
                entry.delete_password()
                    .map_err(|e| TempS3Error::CredentialError(format!("Failed to delete credentials: {}", e)))?;
            } else {
                return Err(TempS3Error::CredentialError("Keyring entry not available".to_string()));
            }
        }
        
        info!("Credentials deleted successfully");
        Ok(())
    }

    pub async fn validate_credentials(&self, credentials: &AwsCredentials) -> Result<bool> {
        info!("Validating AWS credentials");

        let aws_credentials = Credentials::new(
            &credentials.access_key_id,
            &credentials.secret_access_key,
            credentials.session_token.clone(),
            None,
            "temps3",
        );

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(credentials.region.clone()))
            .credentials_provider(aws_credentials)
            .load()
            .await;

        let client = S3Client::new(&config);

        // Test credentials by listing buckets
        match client.list_buckets().send().await {
            Ok(_) => {
                info!("Credentials validated successfully");
                Ok(true)
            }
            Err(e) => {
                warn!("Credential validation failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Comprehensive credential health check with bucket validation
    pub async fn credential_health_check(&self, bucket_name: &str) -> Result<CredentialStatus> {
        info!("Running comprehensive credential health check");

        // Check if credentials exist
        let credentials = match self.load_credentials().await? {
            Some(creds) => creds,
            None => {
                return Ok(CredentialStatus {
                    valid: false,
                    can_access_bucket: false,
                    has_required_permissions: false,
                    error_message: Some("No stored AWS credentials found".to_string()),
                    suggestion: Some("Run 'temps3 init' to set up your AWS credentials".to_string()),
                });
            }
        };

        let aws_credentials = Credentials::new(
            &credentials.access_key_id,
            &credentials.secret_access_key,
            credentials.session_token.clone(),
            None,
            "temps3",
        );

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(credentials.region.clone()))
            .credentials_provider(aws_credentials)
            .load()
            .await;

        let client = S3Client::new(&config);

        // Test 1: Can list buckets?
        let can_list_buckets = match client.list_buckets().send().await {
            Ok(_) => true,
            Err(e) => {
                let error_msg = e.to_string().to_lowercase();
                let (error_type, suggestion) = if error_msg.contains("invalidaccesskeyid") {
                    ("Invalid AWS Access Key ID", "Check your Access Key ID in 'temps3 init'")
                } else if error_msg.contains("signaturedoesnotmatch") {
                    ("Invalid AWS Secret Access Key", "Check your Secret Access Key in 'temps3 init'")
                } else if error_msg.contains("expired") || error_msg.contains("token") {
                    ("Expired AWS credentials", "Refresh your credentials with 'temps3 init'")
                } else {
                    ("AWS authentication failed", "Run 'temps3 init' to update your credentials")
                };

                return Ok(CredentialStatus {
                    valid: false,
                    can_access_bucket: false,
                    has_required_permissions: false,
                    error_message: Some(format!("{}: {}", error_type, e)),
                    suggestion: Some(suggestion.to_string()),
                });
            }
        };

        // Test 2: Can access the configured bucket?
        let can_access_bucket = match client.head_bucket().bucket(bucket_name).send().await {
            Ok(_) => true,
            Err(_) => false, // Bucket might not exist yet, that's okay
        };

        // Test 3: Check specific S3 permissions
        let has_required_permissions = self.check_s3_permissions(&client, bucket_name).await.unwrap_or(false);

        Ok(CredentialStatus {
            valid: can_list_buckets,
            can_access_bucket,
            has_required_permissions,
            error_message: None,
            suggestion: None,
        })
    }

    async fn check_s3_permissions(&self, client: &S3Client, bucket_name: &str) -> Result<bool> {
        // Try basic S3 operations to verify permissions
        let test_key = "temps3-permission-test";
        
        // Test CreateBucket permission (if bucket doesn't exist)
        match client.head_bucket().bucket(bucket_name).send().await {
            Err(_) => {
                // Bucket doesn't exist, test create permission
                match client.create_bucket().bucket(bucket_name).send().await {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            Ok(_) => {
                // Bucket exists, test put/get permissions
                let test_content = "permission test";
                match client
                    .put_object()
                    .bucket(bucket_name)
                    .key(test_key)
                    .body(ByteStream::from_static(test_content.as_bytes()))
                    .send()
                    .await
                {
                    Ok(_) => {
                        // Clean up test object
                        let _ = client.delete_object().bucket(bucket_name).key(test_key).send().await;
                        Ok(true)
                    }
                    Err(_) => Ok(false),
                }
            }
        }
    }

    pub async fn check_permissions(&self, credentials: &AwsCredentials, bucket_name: &str) -> Result<Vec<String>> {
        info!("Checking S3 permissions for bucket: {}", bucket_name);

        let aws_credentials = Credentials::new(
            &credentials.access_key_id,
            &credentials.secret_access_key,
            credentials.session_token.clone(),
            None,
            "temps3",
        );

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(credentials.region.clone()))
            .credentials_provider(aws_credentials)
            .load()
            .await;

        let client = S3Client::new(&config);

        let mut missing_permissions = Vec::new();
        let test_key = "temps3-permission-test";

        // Test PutObject
        if let Err(_) = client
            .put_object()
            .bucket(bucket_name)
            .key(test_key)
            .body(ByteStream::from(b"test".to_vec()))
            .send()
            .await
        {
            missing_permissions.push("s3:PutObject".to_string());
        } else {
            // Clean up test object
            let _ = client
                .delete_object()
                .bucket(bucket_name)
                .key(test_key)
                .send()
                .await;
        }

        // Test GetBucketLifecycleConfiguration
        if let Err(_) = client
            .get_bucket_lifecycle_configuration()
            .bucket(bucket_name)
            .send()
            .await
        {
            missing_permissions.push("s3:GetBucketLifecycleConfiguration".to_string());
        }

        if missing_permissions.is_empty() {
            info!("All required permissions verified");
        } else {
            warn!("Missing permissions: {:?}", missing_permissions);
        }

        Ok(missing_permissions)
    }

    /// Validate that specific credentials can access a specific bucket
    #[allow(dead_code)]
    pub async fn validate_bucket_access(&self, credentials: &AwsCredentials, bucket_name: &str) -> Result<bool> {
        info!("Validating bucket access for: {}", bucket_name);

        let aws_credentials = Credentials::new(
            &credentials.access_key_id,
            &credentials.secret_access_key,
            credentials.session_token.clone(),
            None,
            "temps3",
        );

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(credentials.region.clone()))
            .credentials_provider(aws_credentials)
            .load()
            .await;

        let client = S3Client::new(&config);

        // Test bucket access with head_bucket
        match client.head_bucket().bucket(bucket_name).send().await {
            Ok(_) => {
                info!("Bucket access validated: {}", bucket_name);
                Ok(true)
            }
            Err(e) => {
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("access denied") || error_str.contains("forbidden") {
                    warn!("Access denied to bucket: {}", bucket_name);
                    Ok(false)
                } else if error_str.contains("nosuchbucket") || error_str.contains("not found") {
                    warn!("Bucket does not exist: {}", bucket_name);
                    Ok(false)
                } else {
                    warn!("Bucket validation failed for {}: {}", bucket_name, e);
                    Ok(false)
                }
            }
        }
    }

    fn get_or_create_encryption_key(&self) -> Result<Vec<u8>> {
        if self.use_file_storage {
            // File-based encryption key storage
            let key_path = self.config_dir.join("encryption.key");
            match fs::read_to_string(&key_path) {
                Ok(key_b64) => {
                    general_purpose::STANDARD.decode(key_b64)
                        .map_err(|e| TempS3Error::EncryptionError(format!("Failed to decode encryption key: {}", e)))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Generate new key
                    let rng = SystemRandom::new();
                    let mut key = vec![0u8; 32]; // 256-bit key
                    rng.fill(&mut key)
                        .map_err(|e| TempS3Error::EncryptionError(format!("Failed to generate encryption key: {}", e)))?;

                    let key_b64 = general_purpose::STANDARD.encode(&key);
                    fs::write(&key_path, &key_b64)
                        .map_err(|e| TempS3Error::EncryptionError(format!("Failed to store encryption key: {}", e)))?;

                    Ok(key)
                }
                Err(e) => Err(TempS3Error::EncryptionError(format!("Failed to read encryption key file: {}", e))),
            }
        } else {
            // Keyring-based encryption key storage
            if let Some(ref entry) = self.encryption_entry {
                match entry.get_password() {
                    Ok(key_b64) => {
                        general_purpose::STANDARD.decode(key_b64)
                            .map_err(|e| TempS3Error::EncryptionError(format!("Failed to decode encryption key: {}", e)))
                    }
                    Err(keyring::Error::NoEntry) => {
                        // Generate new key
                        let rng = SystemRandom::new();
                        let mut key = vec![0u8; 32]; // 256-bit key
                        rng.fill(&mut key)
                            .map_err(|e| TempS3Error::EncryptionError(format!("Failed to generate encryption key: {}", e)))?;

                        let key_b64 = general_purpose::STANDARD.encode(&key);
                        entry.set_password(&key_b64)
                            .map_err(|e| TempS3Error::EncryptionError(format!("Failed to store encryption key: {}", e)))?;

                        Ok(key)
                    }
                    Err(e) => Err(TempS3Error::EncryptionError(format!("Failed to access encryption key: {}", e))),
                }
            } else {
                Err(TempS3Error::EncryptionError("Encryption entry not available".to_string()))
            }
        }
    }

    fn get_encryption_key(&self) -> Result<Vec<u8>> {
        if self.use_file_storage {
            // File-based encryption key storage
            let key_path = self.config_dir.join("encryption.key");
            let key_b64 = fs::read_to_string(&key_path)
                .map_err(|e| TempS3Error::EncryptionError(format!("Failed to retrieve encryption key file: {}", e)))?;
            
            general_purpose::STANDARD.decode(key_b64)
                .map_err(|e| TempS3Error::EncryptionError(format!("Failed to decode encryption key: {}", e)))
        } else {
            // Keyring-based encryption key storage
            if let Some(ref entry) = self.encryption_entry {
                let key_b64 = entry.get_password()
                    .map_err(|e| TempS3Error::EncryptionError(format!("Failed to retrieve encryption key: {}", e)))?;
                
                general_purpose::STANDARD.decode(key_b64)
                    .map_err(|e| TempS3Error::EncryptionError(format!("Failed to decode encryption key: {}", e)))
            } else {
                Err(TempS3Error::EncryptionError("Encryption entry not available".to_string()))
            }
        }
    }

    fn encrypt_data(&self, data: &str, key: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| TempS3Error::EncryptionError(format!("Failed to create cipher: {}", e)))?;

        let rng = SystemRandom::new();
        let mut nonce_bytes = vec![0u8; 12]; // 96-bit nonce
        rng.fill(&mut nonce_bytes)
            .map_err(|e| TempS3Error::EncryptionError(format!("Failed to generate nonce: {}", e)))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut ciphertext = cipher.encrypt(nonce, data.as_bytes())
            .map_err(|e| TempS3Error::EncryptionError(format!("Failed to encrypt data: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes;
        result.append(&mut ciphertext);
        
        Ok(result)
    }

    fn decrypt_data(&self, encrypted_data: &[u8], key: &[u8]) -> Result<String> {
        if encrypted_data.len() < 12 {
            return Err(TempS3Error::EncryptionError("Invalid encrypted data length".to_string()));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| TempS3Error::EncryptionError(format!("Failed to create cipher: {}", e)))?;

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| TempS3Error::EncryptionError(format!("Failed to decrypt data: {}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| TempS3Error::EncryptionError(format!("Failed to convert decrypted data to string: {}", e)))
    }
}

pub async fn prompt_for_credentials() -> Result<AwsCredentials> {
    use dialoguer::{Input, Select};

    println!("AWS credentials not found. Let's set them up.");

    let access_key_id: String = Input::new()
        .with_prompt("AWS Access Key ID")
        .interact_text()
        .map_err(|e| TempS3Error::CredentialError(format!("Failed to read access key: {}", e)))?;

    let secret_access_key: String = Input::new()
        .with_prompt("AWS Secret Access Key")
        .interact_text()
        .map_err(|e| TempS3Error::CredentialError(format!("Failed to read secret key: {}", e)))?;

    let regions = vec![
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-central-1",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    ];

    let region_index = Select::new()
        .with_prompt("Select AWS Region")
        .items(&regions)
        .default(0)
        .interact()
        .map_err(|e| TempS3Error::CredentialError(format!("Failed to select region: {}", e)))?;

    let region = regions[region_index].to_string();

    Ok(AwsCredentials {
        access_key_id,
        secret_access_key,
        session_token: None,
        region,
    })
}
