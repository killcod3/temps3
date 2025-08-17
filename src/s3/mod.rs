use crate::cli::TtlDuration;
use crate::credentials::AwsCredentials;
use crate::error::{Result, RetryManager, TempS3Error};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{
    primitives::ByteStream,
    types::{
        CompletedMultipartUpload, CompletedPart, ExpirationStatus, 
        LifecycleExpiration, LifecycleRule, LifecycleRuleFilter, Tag,
    },
    Client as S3Client,
};
use chrono::{DateTime, Utc};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use ring::digest::{Context, SHA256};
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const MULTIPART_THRESHOLD: u64 = 5 * 1024 * 1024; // 5MB
const MAX_CONCURRENT_UPLOADS: usize = 10;
const MAX_S3_PARTS: u64 = 10000; // S3 limit

pub struct S3Service {
    client: S3Client,
    retry_manager: RetryManager,
}

impl S3Service {
    pub async fn new(credentials: &AwsCredentials) -> Result<Self> {
        let aws_credentials = aws_credential_types::Credentials::new(
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

        Ok(Self {
            client,
            retry_manager: RetryManager::new(3, 1000),
        })
    }

    /// Calculate optimal chunk size based on file size for efficient multipart uploads
    fn calculate_optimal_chunk_size(file_size: u64) -> u64 {
        // Adaptive chunk sizing strategy:
        // - Keep parts under S3's 10,000 part limit
        // - Ensure each part is at least 5MB (S3 requirement, except last part)
        // - Balance between few large chunks (efficiency) and parallelism
        
        match file_size {
            // Files < 50MB: Use 5MB chunks (1-10 parts)
            size if size < 50 * 1024 * 1024 => 5 * 1024 * 1024,
            
            // Files 50MB - 500MB: Use 10MB chunks (5-50 parts)
            size if size < 500 * 1024 * 1024 => 10 * 1024 * 1024,
            
            // Files 500MB - 5GB: Use 50MB chunks (10-100 parts)
            size if size < 5 * 1024 * 1024 * 1024 => 50 * 1024 * 1024,
            
            // Files 5GB - 50GB: Use 100MB chunks (50-500 parts)
            size if size < 50 * 1024 * 1024 * 1024 => 100 * 1024 * 1024,
            
            // Files 50GB+: Calculate to stay under 10,000 parts with reasonable chunk size
            size => {
                // Calculate minimum chunk size to stay under MAX_S3_PARTS
                let min_chunk_for_parts = (size + MAX_S3_PARTS - 1) / MAX_S3_PARTS;
                
                // Use at least 500MB for very large files, but ensure we don't exceed part limit
                let preferred_chunk = 500 * 1024 * 1024;
                
                std::cmp::max(min_chunk_for_parts, preferred_chunk)
            }
        }
    }

    /// Get chunk size information for logging and user feedback
    fn get_chunk_info(file_size: u64, chunk_size: u64) -> (u64, String, String) {
        let total_parts = (file_size + chunk_size - 1) / chunk_size;
        let chunk_mb = chunk_size as f64 / (1024.0 * 1024.0);
        let size_desc = format!("{:.0}MB", chunk_mb);
        let strategy_desc = match chunk_mb as u64 {
            5 => "Small files - optimal for quick uploads".to_string(),
            10 => "Medium files - balanced efficiency".to_string(),
            50 => "Large files - optimized throughput".to_string(),
            100 => "Very large files - high-performance chunks".to_string(),
            _ => "Ultra-large files - maximum efficiency".to_string(),
        };
        
        (total_parts, size_desc, strategy_desc)
    }

    pub async fn ensure_bucket_exists(&self, bucket_name: &str) -> Result<()> {
        info!("Ensuring bucket '{}' exists", bucket_name);

        // Validate bucket name first
        if let Err(validation_error) = crate::config::validate_bucket_name(bucket_name) {
            return Err(TempS3Error::ValidationError(format!(
                "Invalid bucket name '{}': {}", bucket_name, validation_error
            )));
        }

        // Check if bucket exists
        match self.client.head_bucket().bucket(bucket_name).send().await {
            Ok(_) => {
                info!("Bucket '{}' exists", bucket_name);
                return Ok(());
            }
            Err(e) => {
                debug!("Bucket check failed: {}", e);
                // Bucket might not exist, try to create it
            }
        }

        // Try to create bucket
        info!("Creating bucket '{}'", bucket_name);
        match self.retry_manager
            .retry_with_backoff(|| async {
                self.client
                    .create_bucket()
                    .bucket(bucket_name)
                    .send()
                    .await
                    .map_err(|e| TempS3Error::S3Error(e.into()))
            })
            .await
        {
            Ok(_) => {
                info!("Bucket '{}' created successfully", bucket_name);
                Ok(())
            }
            Err(TempS3Error::S3Error(aws_error)) => {
                // Check if it's a bucket already exists error from another account
                let error_str = aws_error.to_string().to_lowercase();
                if error_str.contains("bucketalreadyexists") || error_str.contains("bucket already exists") {
                    Err(TempS3Error::ConfigError(format!(
                        "Bucket name '{}' is already taken by another AWS account. \
                        Please update your configuration with a unique bucket name. \
                        You can generate a new one by running 'temps3 init' or manually \
                        editing the config file at: {}",
                        bucket_name,
                        crate::config::get_config_path().display()
                    )))
                } else if error_str.contains("bucketalreadyownedby") {
                    Err(TempS3Error::ConfigError(format!(
                        "Bucket '{}' is already owned by a different AWS account. \
                        Please choose a different bucket name or update your AWS credentials.",
                        bucket_name
                    )))
                } else {
                    Err(TempS3Error::S3Error(aws_error))
                }
            }
            Err(e) => Err(e),
        }
    }

    pub async fn configure_lifecycle_policies(&self, bucket_name: &str) -> Result<()> {
        info!("Configuring lifecycle policies for bucket '{}'", bucket_name);

        let rules = vec![
            self.create_lifecycle_rule("1d", 1)?,
            self.create_lifecycle_rule("3d", 3)?,
            self.create_lifecycle_rule("5d", 5)?,
        ];

        self.retry_manager
            .retry_with_backoff(|| async {
                let lifecycle_config = aws_sdk_s3::types::BucketLifecycleConfiguration::builder()
                    .set_rules(Some(rules.clone()))
                    .build()
                    .map_err(|e| TempS3Error::Unknown(format!("Failed to build lifecycle config: {}", e)))?;
                
                self.client
                    .put_bucket_lifecycle_configuration()
                    .bucket(bucket_name)
                    .lifecycle_configuration(lifecycle_config)
                    .send()
                    .await
                    .map_err(|e| TempS3Error::S3Error(e.into()))
            })
            .await?;

        info!("Lifecycle policies configured successfully");
        Ok(())
    }

    pub async fn upload_file(
        &self,
        file_path: &Path,
        bucket_name: &str,
        s3_key: &str,
        ttl: &TtlDuration,
        verbose: bool,
    ) -> Result<(String, i64)> {
        info!("Starting upload: {} -> s3://{}/{}", file_path.display(), bucket_name, s3_key);

        let file_size = tokio::fs::metadata(file_path).await?.len();
        let checksum = self.calculate_file_checksum(file_path).await?;

        if file_size < MULTIPART_THRESHOLD {
            self.upload_single_part(file_path, bucket_name, s3_key, ttl, verbose).await?;
        } else {
            self.upload_multipart(file_path, bucket_name, s3_key, ttl, verbose).await?;
        }

        info!("Upload completed successfully");
        Ok((checksum, file_size as i64))
    }

    async fn upload_single_part(
        &self,
        file_path: &Path,
        bucket_name: &str,
        s3_key: &str,
        ttl: &TtlDuration,
        verbose: bool,
    ) -> Result<()> {
        if verbose {
            info!("Uploading file as single part...");
        }

        // Always show progress bar for uploads
        let pb = ProgressBar::new(1);
        let template = if verbose {
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}"
        } else {
            "{bar:40.cyan/blue} {pos:>7}/{len:7} {msg}"
        };
        match ProgressStyle::default_bar().template(template) {
            Ok(style) => {
                pb.set_style(style.progress_chars("##-"));
            },
            Err(e) => {
                warn!("Failed to set progress bar style: {}. Using default style.", e);
                // Continue with default style - non-critical error
            }
        }
        pb.set_message("Uploading...");
        let progress = Some(pb);

        let file_content = tokio::fs::read(file_path).await?;

        self.retry_manager
            .retry_with_backoff(|| async {
                let body = ByteStream::from(file_content.clone());
                self.client
                    .put_object()
                    .bucket(bucket_name)
                    .key(s3_key)
                    .body(body)
                    .tagging(&format!("ttl={}", ttl.as_tag()))
                    .send()
                    .await
                    .map_err(|e| TempS3Error::S3Error(e.into()))
            })
            .await?;

        if let Some(pb) = progress {
            pb.inc(1);
            pb.finish_with_message("Upload complete");
        }

        Ok(())
    }

    async fn upload_multipart(
        &self,
        file_path: &Path,
        bucket_name: &str,
        s3_key: &str,
        ttl: &TtlDuration,
        verbose: bool,
    ) -> Result<()> {
        let file_size = tokio::fs::metadata(file_path).await?.len();
        let chunk_size = Self::calculate_optimal_chunk_size(file_size);
        let total_parts = (file_size + chunk_size - 1) / chunk_size;
        let (_, chunk_desc, strategy_desc) = Self::get_chunk_info(file_size, chunk_size);

        if verbose {
            info!("Uploading file using multipart upload...");
            info!("📊 File size: {:.2} MB", file_size as f64 / (1024.0 * 1024.0));
            info!("📦 Chunk size: {} ({})", chunk_desc, strategy_desc);
            info!("🔢 Total parts: {}", total_parts);
        }

        // Always show progress bar for uploads
        let pb = ProgressBar::new(total_parts);
        let template = if verbose {
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}"
        } else {
            "{bar:40.cyan/blue} {pos:>7}/{len:7} {msg}"
        };
        match ProgressStyle::default_bar().template(template) {
            Ok(style) => {
                pb.set_style(style.progress_chars("##-"));
            },
            Err(e) => {
                warn!("Failed to set progress bar style: {}. Using default style.", e);
                // Continue with default style - non-critical error
            }
        }
        pb.set_message("Uploading parts...");
        let progress = Some(Arc::new(pb));

        // Initiate multipart upload
        let create_output = self
            .retry_manager
            .retry_with_backoff(|| async {
                self.client
                    .create_multipart_upload()
                    .bucket(bucket_name)
                    .key(s3_key)
                    .tagging(&format!("ttl={}", ttl.as_tag()))
                    .send()
                    .await
                    .map_err(|e| TempS3Error::S3Error(e.into()))
            })
            .await?;

        let upload_id = create_output
            .upload_id()
            .ok_or_else(|| TempS3Error::UploadError("No upload ID received".to_string()))?;

        // Upload parts
        let completed_parts = self
            .upload_parts(file_path, bucket_name, s3_key, upload_id, total_parts, chunk_size, progress.clone())
            .await?;

        // Complete multipart upload
        let completed_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();

        self.retry_manager
            .retry_with_backoff(|| async {
                self.client
                    .complete_multipart_upload()
                    .bucket(bucket_name)
                    .key(s3_key)
                    .upload_id(upload_id)
                    .multipart_upload(completed_upload.clone())
                    .send()
                    .await
                    .map_err(|e| TempS3Error::S3Error(e.into()))
            })
            .await?;

        if let Some(pb) = progress {
            pb.finish_with_message("Multipart upload complete");
        }

        Ok(())
    }

    async fn upload_parts(
        &self,
        file_path: &Path,
        bucket_name: &str,
        s3_key: &str,
        upload_id: &str,
        total_parts: u64,
        chunk_size: u64,
        progress: Option<Arc<ProgressBar>>,
    ) -> Result<Vec<CompletedPart>> {
        let file_size = tokio::fs::metadata(file_path).await?.len();
        let mut completed_parts = Vec::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UPLOADS));

        let mut tasks = Vec::new();

        for part_number in 1..=total_parts {
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
            let client = self.client.clone();
            let bucket_name = bucket_name.to_string();
            let s3_key = s3_key.to_string();
            let upload_id = upload_id.to_string();
            let progress = progress.clone();
            let file_path = file_path.to_path_buf();

            // Calculate the byte range for this part
            let start_byte = (part_number - 1) * chunk_size;
            let end_byte = std::cmp::min(start_byte + chunk_size - 1, file_size - 1);
            let part_size = end_byte - start_byte + 1;

            let task = tokio::spawn(async move {
                let _permit = permit; // Keep permit alive

                // Read chunk data from specific byte range
                let mut file = File::open(&file_path).await?;
                file.seek(std::io::SeekFrom::Start(start_byte)).await?;
                
                let mut buffer = vec![0u8; part_size as usize];
                file.read_exact(&mut buffer).await?;

                let retry_manager = RetryManager::new(3, 1000);
                let result = retry_manager
                    .retry_with_backoff(|| async {
                        let body = ByteStream::from(buffer.clone());
                        client
                            .upload_part()
                            .bucket(&bucket_name)
                            .key(&s3_key)
                            .upload_id(&upload_id)
                            .part_number(part_number as i32)
                            .body(body)
                            .send()
                            .await
                            .map_err(|e| TempS3Error::S3Error(e.into()))
                    })
                    .await?;

                let etag = result
                    .e_tag()
                    .ok_or_else(|| TempS3Error::UploadError("No ETag received for part".to_string()))?;

                let completed_part = CompletedPart::builder()
                    .part_number(part_number as i32)
                    .e_tag(etag)
                    .build();

                if let Some(pb) = progress {
                    pb.inc(1);
                }

                Ok::<CompletedPart, TempS3Error>(completed_part)
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete
        for task in tasks {
            let completed_part = task.await
                .map_err(|e| TempS3Error::UploadError(format!("Task join error: {}", e)))??;
            completed_parts.push(completed_part);
        }

        // Sort parts by part number
        completed_parts.sort_by_key(|part| part.part_number());

        Ok(completed_parts)
    }

    pub async fn generate_presigned_url(
        &self,
        bucket_name: &str,
        s3_key: &str,
        expiry_days: u32,
    ) -> Result<(String, DateTime<Utc>)> {
        info!("Generating presigned URL for s3://{}/{}", bucket_name, s3_key);

        let expires_in = std::time::Duration::from_secs(expiry_days as u64 * 24 * 60 * 60);
        let expiry_time = Utc::now() + chrono::Duration::seconds(expires_in.as_secs() as i64);

        let presigning_config = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in)
            .map_err(|e| TempS3Error::Unknown(format!("Presigning config error: {}", e)))?;

        let presigned_request = self
            .client
            .get_object()
            .bucket(bucket_name)
            .key(s3_key)
            .presigned(presigning_config)
            .await
            .map_err(|e| TempS3Error::S3Error(e.into()))?;

        let url = presigned_request.uri().to_string();
        info!("Presigned URL generated, expires at: {}", expiry_time);

        Ok((url, expiry_time))
    }

    /// Empty the entire bucket by deleting all objects with the temps3 prefix
    pub async fn empty_bucket(&self, bucket_name: &str) -> Result<u64> {
        info!("Starting bucket empty operation for bucket: {}", bucket_name);
        
        let mut deleted_count = 0u64;
        let mut continuation_token: Option<String> = None;

        loop {
            // List objects with temps3 prefix
            let mut list_request = self.client
                .list_objects_v2()
                .bucket(bucket_name)
                .prefix("temps3/");

            if let Some(token) = continuation_token {
                list_request = list_request.continuation_token(token);
            }

            let list_response = self.retry_manager
                .retry_with_backoff(|| async {
                    list_request
                        .clone()
                        .send()
                        .await
                        .map_err(|e| TempS3Error::S3Error(e.into()))
                })
                .await?;

            let objects = list_response.contents();
            
            if objects.is_empty() {
                break;
            }

            // Delete objects in batches
            let batch_size = 1000; // S3 delete batch limit
            for chunk in objects.chunks(batch_size) {
                let delete_objects: Vec<_> = chunk.iter()
                    .filter_map(|obj| obj.key())
                    .map(|key| {
                        aws_sdk_s3::types::ObjectIdentifier::builder()
                            .key(key)
                            .build()
                            .unwrap()
                    })
                    .collect();

                if !delete_objects.is_empty() {
                    let delete_request = aws_sdk_s3::types::Delete::builder()
                        .set_objects(Some(delete_objects.clone()))
                        .quiet(true)
                        .build()
                        .unwrap();

                    self.retry_manager
                        .retry_with_backoff(|| async {
                            self.client
                                .delete_objects()
                                .bucket(bucket_name)
                                .delete(delete_request.clone())
                                .send()
                                .await
                                .map_err(|e| TempS3Error::S3Error(e.into()))?;
                            Ok::<(), TempS3Error>(())
                        })
                        .await?;

                    deleted_count += delete_objects.len() as u64;
                    info!("Deleted {} objects (total: {})", delete_objects.len(), deleted_count);
                }
            }

            // Check if there are more objects
            if list_response.is_truncated() == Some(true) {
                continuation_token = list_response.next_continuation_token().map(|s| s.to_string());
            } else {
                break;
            }
        }

        info!("Bucket empty operation completed. Deleted {} objects", deleted_count);
        Ok(deleted_count)
    }

    async fn calculate_file_checksum(&self, file_path: &Path) -> Result<String> {
        let mut file = File::open(file_path).await?;
        let mut context = Context::new(&SHA256);
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            context.update(&buffer[..bytes_read]);
        }

        let digest = context.finish();
        Ok(hex::encode(digest.as_ref()))
    }

    fn create_lifecycle_rule(&self, ttl_tag: &str, days: i32) -> Result<LifecycleRule> {
        let tag = Tag::builder()
            .key("ttl")
            .value(ttl_tag)
            .build()
            .map_err(|e| TempS3Error::LifecycleRuleError(format!("Failed to build TTL tag: {}", e)))?;

        LifecycleRule::builder()
            .id(format!("temps3-{}-day-expiration", days))
            .status(ExpirationStatus::Enabled)
            .filter(
                LifecycleRuleFilter::builder()
                    .tag(tag)
                    .build()
            )
            .expiration(
                LifecycleExpiration::builder()
                    .days(days)
                    .build()
            )
            .build()
            .map_err(|e| TempS3Error::LifecycleRuleError(format!("Failed to build lifecycle rule: {}", e)))
    }

    pub fn generate_s3_key(file_name: &str) -> String {
        let timestamp = Utc::now().format("%Y/%m/%d/%H%M%S");
        let uuid = uuid::Uuid::new_v4();
        format!("temps3/{}/{}-{}", timestamp, uuid, file_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_s3_key() {
        let key = S3Service::generate_s3_key("test.txt");
        assert!(key.starts_with("temps3/"));
        assert!(key.ends_with("-test.txt"));
        assert!(key.contains("/"));
    }

    #[test]
    fn test_ttl_duration() {
        assert_eq!(TtlDuration::OneDay.as_tag(), "1d");
        assert_eq!(TtlDuration::ThreeDays.as_tag(), "3d");
        assert_eq!(TtlDuration::FiveDays.as_tag(), "5d");
        
        assert_eq!(TtlDuration::OneDay.as_days(), 1);
        assert_eq!(TtlDuration::ThreeDays.as_days(), 3);
        assert_eq!(TtlDuration::FiveDays.as_days(), 5);
    }
}
