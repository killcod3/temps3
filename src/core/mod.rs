use crate::cli::TtlDuration;
use crate::config::{AppState, Config};
use crate::credentials::{CredentialManager, prompt_for_credentials};
use crate::error::{Result, TempS3Error};
use crate::s3::S3Service;
use crate::storage::{StorageManager, UploadRecord};
use console::{style, Term};
use log::{info, warn};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};

pub struct TempS3App {
    config: Config,
    state: AppState,
    credential_manager: CredentialManager,
    storage_manager: StorageManager,
    s3_service: Option<S3Service>,
}

impl TempS3App {
    pub async fn new() -> Result<Self> {
        info!("Initializing TempS3 application");

        let config = Config::load().await?;
        let state = AppState::load().await?;
        let credential_manager = CredentialManager::new()?;
        let storage_manager = StorageManager::new(&config.database_path).await?;

        let mut app = Self {
            config,
            state,
            credential_manager,
            storage_manager,
            s3_service: None,
        };

        // Initialize S3 service if credentials are available
        if let Some(credentials) = app.credential_manager.load_credentials().await? {
            app.s3_service = Some(S3Service::new(&credentials).await?);
        }

        Ok(app)
    }

    pub async fn init(&self) -> Result<()> {
        let term = Term::stdout();
        
        term.write_line(&format!("🚀 {}", style("Initializing TempS3").bold().blue()))?;
        term.write_line("")?;

        // Check if already initialized
        if self.state.initialized {
            term.write_line("⚠️  TempS3 is already initialized.")?;
            term.write_line("Use 'temps3 config' to modify configuration.")?;
            return Ok(());
        }

        // Step 1: Get or validate credentials
        let credentials = match self.credential_manager.load_credentials().await? {
            Some(creds) => {
                term.write_line("📋 Found existing credentials. Validating...")?;
                if self.credential_manager.validate_credentials(&creds).await? {
                    term.write_line(&format!("✅ {}", style("Credentials validated").green()))?;
                    creds
                } else {
                    term.write_line("❌ Stored credentials are invalid. Please provide new ones.")?;
                    let new_creds = prompt_for_credentials().await?;
                    self.credential_manager.store_credentials(&new_creds).await?;
                    new_creds
                }
            }
            None => {
                term.write_line("🔑 No credentials found. Let's set them up.")?;
                let creds = prompt_for_credentials().await?;
                
                term.write_line("🔍 Validating credentials...")?;
                if !self.credential_manager.validate_credentials(&creds).await? {
                    return Err(TempS3Error::CredentialError(
                        "Invalid AWS credentials provided".to_string(),
                    ));
                }
                
                self.credential_manager.store_credentials(&creds).await?;
                term.write_line(&format!("✅ {}", style("Credentials stored securely").green()))?;
                creds
            }
        };

        // Step 2: Initialize S3 service
        let s3_service = S3Service::new(&credentials).await?;

        // Step 3: Ensure bucket exists
        term.write_line(&format!("🪣 Setting up S3 bucket: {}", self.config.bucket_name))?;
        
        match s3_service.ensure_bucket_exists(&self.config.bucket_name).await {
            Ok(_) => {
                term.write_line(&format!("✅ {}", style("Bucket ready").green()))?;
            }
            Err(TempS3Error::ConfigError(msg)) => {
                // Handle bucket name conflicts
                term.write_line(&format!("❌ {}", style("Bucket setup failed").red()))?;
                term.write_line(&msg)?;
                term.write_line("")?;
                term.write_line("💡 Here are some alternative bucket names you can use:")?;
                
                for i in 1..=3 {
                    let alternative = crate::config::generate_unique_bucket_name();
                    term.write_line(&format!("   {}. {}", i, alternative))?;
                }
                
                term.write_line("")?;
                term.write_line("To use an alternative bucket name:")?;
                term.write_line(&format!("   📝 Edit: {}", crate::config::get_config_path().display()))?;
                term.write_line("   🔄 Update the 'bucket_name' field")?;
                term.write_line("   🚀 Run 'temps3 init' again")?;
                
                return Err(TempS3Error::ConfigError("Bucket setup failed. Please update the bucket name and try again.".to_string()));
            }
            Err(e) => return Err(e),
        }

        // Step 4: Configure lifecycle policies
        term.write_line("⏰ Configuring automatic expiration policies...")?;
        s3_service.configure_lifecycle_policies(&self.config.bucket_name).await?;
        term.write_line(&format!("✅ {}", style("Lifecycle policies configured").green()))?;

        // Step 5: Check permissions
        term.write_line("🔒 Checking S3 permissions...")?;
        let missing_permissions = self.credential_manager
            .check_permissions(&credentials, &self.config.bucket_name)
            .await?;
        
        if !missing_permissions.is_empty() {
            warn!("Missing permissions: {:?}", missing_permissions);
            term.write_line(&format!("⚠️  {}: {:?}", 
                style("Missing permissions").yellow(),
                missing_permissions
            ))?;
            term.write_line("The application may not work correctly without these permissions.")?;
        } else {
            term.write_line(&format!("✅ {}", style("All permissions verified").green()))?;
        }

        // Step 6: Update state
        let mut new_state = self.state.clone();
        new_state.initialized = true;
        new_state.last_bucket_check = Some(chrono::Utc::now());
        new_state.credentials_validated = true;
        new_state.save().await?;

        term.write_line("")?;
        term.write_line(&format!("🎉 {}", style("TempS3 initialization complete!").bold().green()))?;
        term.write_line("")?;
        term.write_line("You can now upload files using:")?;
        term.write_line(&format!("  {}", style("temps3 upload <file_path>").cyan()))?;
        term.write_line("")?;

        Ok(())
    }

    pub async fn upload(&self, file_path: PathBuf, ttl: TtlDuration, verbose: bool) -> Result<()> {
        let term = Term::stdout();

        // Check if initialized
        if !self.state.initialized {
            return Err(TempS3Error::ConfigError(
                "TempS3 not initialized. Run 'temps3 init' first.".to_string(),
            ));
        }

        // Validate file exists and is readable
        if !file_path.exists() {
            return Err(TempS3Error::FileSystemError(
                std::io::Error::new(std::io::ErrorKind::NotFound, "File not found"),
            ));
        }

        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| TempS3Error::ValidationError("Invalid file name".to_string()))?
            .to_string();

        if verbose {
            term.write_line(&format!("📁 File: {}", file_path.display()))?;
            term.write_line(&format!("⏱️  TTL: {}", ttl.as_tag()))?;
        }

        // Get S3 service
        let s3_service = self.get_s3_service().await?;

        // Generate S3 key
        let s3_key = S3Service::generate_s3_key(&file_name);
        
        if verbose {
            term.write_line(&format!("🔑 S3 Key: {}", s3_key))?;
        }

        // Upload file
        term.write_line(&format!("⬆️  {}", style("Uploading file...").blue()))?;
        let (checksum, file_size) = match s3_service
            .upload_file(&file_path, &self.config.bucket_name, &s3_key, &ttl, verbose)
            .await
        {
            Ok(result) => result,
            Err(TempS3Error::S3Error(aws_error)) => {
                let friendly_error = TempS3Error::from_s3_error(aws_error);
                term.write_line(&friendly_error.user_friendly_message())?;
                return Err(friendly_error);
            }
            Err(e) => return Err(e),
        };

        // Generate presigned URL
        let (presigned_url, url_expiry) = match s3_service
            .generate_presigned_url(
                &self.config.bucket_name,
                &s3_key,
                self.config.presigned_url_expiry_days,
            )
            .await
        {
            Ok(result) => result,
            Err(TempS3Error::S3Error(aws_error)) => {
                let friendly_error = TempS3Error::from_s3_error(aws_error);
                term.write_line(&friendly_error.user_friendly_message())?;
                return Err(friendly_error);
            }
            Err(e) => return Err(e),
        };

        // Store record in database
        let upload_record = UploadRecord::new(
            file_name,
            file_path.to_string_lossy().to_string(),
            file_size,
            s3_key,
            self.config.bucket_name.clone(),
            ttl.as_tag().to_string(),
            presigned_url.clone(),
            url_expiry,
            checksum,
        );

        self.storage_manager.store_upload(&upload_record).await?;

        // Display results
        term.write_line("")?;
        term.write_line(&format!("✅ {}", style("Upload successful!").bold().green()))?;
        term.write_line("")?;
        term.write_line(&format!("📊 File size: {}", format_file_size(file_size)))?;
        term.write_line(&format!("🏷️  TTL: {} (expires in {} days)", ttl.as_tag(), ttl.as_days()))?;
        term.write_line(&format!("🔗 Download URL: {}", style(&presigned_url).blue().underlined()))?;
        term.write_line(&format!("⏰ URL expires: {}", url_expiry.format("%Y-%m-%d %H:%M:%S UTC")))?;
        term.write_line("")?;

        if verbose {
            term.write_line(&format!("🆔 Upload ID: {}", upload_record.id))?;
            term.write_line(&format!("🔐 Checksum: {}", upload_record.checksum))?;
        }

        Ok(())
    }

    pub async fn list_with_options(
        &self,
        ttl_filter: Option<String>,
        status_filter: String,
        limit: u32,
        page: u32,
        sort_by: String,
        order: String,
        search_pattern: Option<String>,
        verbose: bool,
    ) -> Result<()> {
        let term = Term::stdout();

        // Validate inputs
        if limit == 0 || limit > 100 {
            return Err(TempS3Error::ValidationError("Limit must be between 1 and 100".to_string()));
        }
        
        if page == 0 {
            return Err(TempS3Error::ValidationError("Page must be 1 or greater".to_string()));
        }
        
        if !["active", "expired", "all"].contains(&status_filter.as_str()) {
            return Err(TempS3Error::ValidationError("Status must be 'active', 'expired', or 'all'".to_string()));
        }
        
        if !["date", "size", "name", "expiry"].contains(&sort_by.as_str()) {
            return Err(TempS3Error::ValidationError("Sort must be 'date', 'size', 'name', or 'expiry'".to_string()));
        }
        
        if !["asc", "desc"].contains(&order.as_str()) {
            return Err(TempS3Error::ValidationError("Order must be 'asc' or 'desc'".to_string()));
        }

        // Build filter description
        let mut filter_parts = Vec::new();
        if let Some(ref ttl) = ttl_filter {
            filter_parts.push(format!("TTL: {}", ttl));
        }
        if status_filter != "all" {
            filter_parts.push(format!("Status: {}", status_filter));
        }
        if let Some(ref pattern) = search_pattern {
            filter_parts.push(format!("Search: \"{}\"", pattern));
        }
        
        let filter_desc = if filter_parts.is_empty() {
            "All uploads".to_string()
        } else {
            format!("Filtered by: {}", filter_parts.join(", "))
        };

        term.write_line(&format!("📋 {} ({})", 
            style("Upload History").bold().blue(),
            style(&filter_desc).dim()
        ))?;
        term.write_line("")?;

        let (uploads, total_count) = self.storage_manager.list_uploads_advanced(
            ttl_filter.as_deref(),
            &status_filter,
            limit,
            page,
            &sort_by,
            &order,
            search_pattern.as_deref(),
        ).await?;

        if uploads.is_empty() {
            if total_count == 0 {
                term.write_line("No uploads found.")?;
                term.write_line("Use 'temps3 upload <file_path>' to upload your first file.")?;
            } else {
                term.write_line(&format!("No uploads found on page {}.", page))?;
                let total_pages = (total_count + limit as u64 - 1) / limit as u64;
                term.write_line(&format!("Try a page between 1 and {}.", total_pages))?;
            }
            return Ok(());
        }

        // Display pagination info
        let total_pages = (total_count + limit as u64 - 1) / limit as u64;
        let start_item = ((page - 1) * limit) + 1;
        let end_item = std::cmp::min(page * limit, total_count as u32);
        
        term.write_line(&format!("📄 Page {} of {} ({}-{} of {} uploads)", 
            page, total_pages, start_item, end_item, total_count
        ))?;
        term.write_line("")?;

        // Display uploads
        for (index, upload) in uploads.iter().enumerate() {
            let status = if upload.url_expiry > chrono::Utc::now() {
                style("🟢 Active").green()
            } else {
                style("🔴 Expired").red()
            };

            let item_number = start_item + index as u32;
            term.write_line(&format!("{}. {} - {}", 
                item_number,
                style(&upload.file_name).bold(),
                status
            ))?;
            
            if verbose {
                term.write_line(&format!("   🆔 ID: {}", style(&upload.id).dim()))?;
                term.write_line(&format!("   🗂️  S3 Key: {}", style(&upload.s3_key).dim()))?;
            }
            
            term.write_line(&format!("   📁 Size: {}", format_file_size(upload.file_size)))?;
            term.write_line(&format!("   ⏱️  TTL: {}", upload.ttl_tag))?;
            term.write_line(&format!("   📅 Uploaded: {}", 
                upload.upload_date.format("%Y-%m-%d %H:%M:%S UTC")
            ))?;
            
            if upload.url_expiry > chrono::Utc::now() {
                if verbose {
                    term.write_line(&format!("   🔗 URL: {}", style(&upload.presigned_url).blue().underlined()))?;
                } else {
                    term.write_line(&format!("   🔗 URL: {}", style("Available (use --verbose to show)").blue()))?;
                }
                term.write_line(&format!("   ⏰ Expires: {}", 
                    upload.url_expiry.format("%Y-%m-%d %H:%M:%S UTC")
                ))?;
            } else {
                term.write_line(&format!("   ❌ {}", style("URL expired").red()))?;
            }
            
            if verbose {
                term.write_line(&format!("   🔐 Checksum: {}", style(&upload.checksum).dim()))?;
            }
            
            term.write_line("")?;
        }

        // Show navigation hints
        if total_pages > 1 {
            term.write_line(&format!("💡 Navigation:"))?;
            if page > 1 {
                term.write_line(&format!("   ⬅️  Previous: --page {}", page - 1))?;
            }
            if (page as u64) < total_pages {
                term.write_line(&format!("   ➡️  Next: --page {}", page + 1))?;
            }
            term.write_line("")?;
        }

        // Show filter hints
        term.write_line("💡 Filter options:")?;
        term.write_line("   --ttl 1d|3d|5d     Filter by TTL duration")?;
        term.write_line("   --status active|expired|all    Filter by status")?;
        term.write_line("   --search <pattern>     Search file names")?;
        term.write_line("   --sort date|size|name|expiry   Sort by field")?;
        term.write_line("   --order asc|desc       Sort order")?;
        term.write_line("   --verbose              Show detailed info")?;

        Ok(())
    }

    pub async fn config(&self, check_credentials: bool) -> Result<()> {
        let term = Term::stdout();

        term.write_line(&format!("⚙️  {}", style("TempS3 Configuration").bold().blue()))?;
        term.write_line("")?;

        // Display current configuration
        term.write_line(&format!("📍 AWS Region: {}", self.config.aws_region))?;
        term.write_line(&format!("🪣 Bucket Name: {}", self.config.bucket_name))?;
        term.write_line(&format!("⏰ Presigned URL Expiry: {} days", self.config.presigned_url_expiry_days))?;
        term.write_line(&format!(" Max Concurrent Uploads: {}", self.config.max_concurrent_uploads))?;
        term.write_line(&format!("🔁 Max Retries: {}", self.config.max_retries))?;
        term.write_line(&format!("💾 Database Path: {}", self.config.database_path.display()))?;
        term.write_line(&format!("📊 Log Level: {}", self.config.log_level))?;
        term.write_line("")?;

        // Display state information
        term.write_line(&format!("📋 {}", style("Application State").bold()))?;
        term.write_line(&format!("✅ Initialized: {}", 
            if self.state.initialized { "Yes" } else { "No" }
        ))?;
        term.write_line(&format!("🔐 Credentials Validated: {}", 
            if self.state.credentials_validated { "Yes" } else { "No" }
        ))?;
        
        if let Some(last_check) = self.state.last_bucket_check {
            term.write_line(&format!("🕐 Last Bucket Check: {}", 
                last_check.format("%Y-%m-%d %H:%M:%S UTC")
            ))?;
        }

        // If check_credentials flag is provided, run credential health check
        if check_credentials {
            term.write_line("")?;
            term.write_line(&format!("🔍 {}", style("Credential Health Check").bold().yellow()))?;
            
            match self.credential_manager.credential_health_check(&self.config.bucket_name).await {
                Ok(status) => {
                    if status.valid {
                        term.write_line(&format!("✅ {}", style("AWS credentials are valid").green()))?;
                        term.write_line(&format!("🪣 Bucket access: {}", 
                            if status.can_access_bucket { 
                                style("OK").green() 
                            } else { 
                                style("Bucket not found (will be created)").yellow() 
                            }
                        ))?;
                        term.write_line(&format!("📝 Required permissions: {}", 
                            if status.has_required_permissions { 
                                style("OK").green() 
                            } else { 
                                style("Limited (may affect some operations)").yellow() 
                            }
                        ))?;
                    } else {
                        term.write_line(&format!("❌ {}", style("Credential validation failed").red()))?;
                        if let Some(error) = status.error_message {
                            term.write_line(&format!("   Error: {}", error))?;
                        }
                        if let Some(suggestion) = status.suggestion {
                            term.write_line(&format!("💡 {}", suggestion))?;
                        }
                    }
                }
                Err(e) => {
                    term.write_line(&format!("❌ Failed to check credentials: {}", e.user_friendly_message()))?;
                }
            }
        }

        term.write_line("")?;
        term.write_line("To modify configuration, edit the config file at:")?;
        term.write_line(&format!("📁 {}", crate::config::get_config_path().display()))?;

        Ok(())
    }

    pub async fn purge_database(&self, force: bool) -> Result<()> {
        let term = Term::stdout();

        term.write_line(&format!("🗑️  {}", style("Purge Database").bold().red()))?;
        term.write_line("")?;

        // Get count of uploads
        let total_uploads = self.storage_manager.count_all_uploads().await?;
        let active_uploads = self.storage_manager.count_active_uploads().await?;

        if total_uploads == 0 {
            term.write_line("No uploads found in database.")?;
            return Ok(());
        }

        term.write_line(&format!("📊 Database contains {} uploads:", total_uploads))?;
        term.write_line(&format!("   🟢 Active: {}", active_uploads))?;
        term.write_line(&format!("   🔴 Expired: {}", total_uploads - active_uploads))?;
        term.write_line("")?;

        term.write_line(&format!("⚠️  {}", style("WARNING: This will permanently delete ALL upload records from the local database!").bold().red()))?;
        term.write_line("   • Download URLs will be lost")?;
        term.write_line("   • Upload history will be erased")?;
        term.write_line("   • Files in S3 will NOT be deleted")?;
        term.write_line("")?;

        // Confirmation unless force flag is used
        if !force {
            term.write_line("Type 'PURGE' to confirm database purge:")?;
            let input = self.read_user_confirmation().await?;
            
            if input != "PURGE" {
                term.write_line("❌ Operation cancelled.")?;
                return Ok(());
            }
        }

        term.write_line("🗑️  Purging database...")?;
        let deleted_count = self.storage_manager.purge_all_uploads().await?;

        term.write_line("")?;
        term.write_line(&format!("✅ {}", style("Database purged successfully!").bold().green()))?;
        term.write_line(&format!("   📊 Deleted {} upload records", deleted_count))?;

        Ok(())
    }

    pub async fn empty_bucket(&self, force: bool) -> Result<()> {
        let term = Term::stdout();

        term.write_line(&format!("🪣 {}", style("Empty S3 Bucket").bold().red()))?;
        term.write_line("")?;

        // Check if initialized
        if !self.state.initialized {
            return Err(TempS3Error::ConfigError(
                "TempS3 not initialized. Run 'temps3 init' first.".to_string(),
            ));
        }

        // Get S3 service
        let s3_service = self.get_s3_service().await?;

        // Get database stats
        let total_uploads = self.storage_manager.count_all_uploads().await?;
        let active_uploads = self.storage_manager.count_active_uploads().await?;

        term.write_line(&format!("📊 Current state:"))?;
        term.write_line(&format!("   🪣 Bucket: {}", self.config.bucket_name))?;
        term.write_line(&format!("   📊 Database uploads: {}", total_uploads))?;
        term.write_line(&format!("   🟢 Active: {}", active_uploads))?;
        term.write_line(&format!("   🔴 Expired: {}", total_uploads - active_uploads))?;
        term.write_line("")?;

        term.write_line(&format!("⚠️  {}", style("WARNING: This will:").bold().red()))?;
        term.write_line("   • Delete ALL files from the S3 bucket (temps3/ prefix)")?;
        term.write_line("   • Mark all local database entries as expired")?;
        term.write_line("   • Make all existing download URLs invalid")?;
        term.write_line("   • This action CANNOT be undone!")?;
        term.write_line("")?;

        // Confirmation unless force flag is used
        if !force {
            term.write_line(&format!("Type 'EMPTY {}' to confirm bucket emptying:", self.config.bucket_name))?;
            let input = self.read_user_confirmation().await?;
            
            let expected = format!("EMPTY {}", self.config.bucket_name);
            if input != expected {
                term.write_line("❌ Operation cancelled.")?;
                return Ok(());
            }
        }

        // Empty the S3 bucket
        term.write_line("🗑️  Emptying S3 bucket...")?;
        let deleted_objects = s3_service.empty_bucket(&self.config.bucket_name).await?;

        // Mark all database entries as expired
        term.write_line("⏰ Marking database entries as expired...")?;
        let expired_count = self.storage_manager.expire_all_uploads().await?;

        term.write_line("")?;
        term.write_line(&format!("✅ {}", style("Bucket emptied successfully!").bold().green()))?;
        term.write_line(&format!("   🗑️  Deleted {} objects from S3", deleted_objects))?;
        term.write_line(&format!("   ⏰ Expired {} database entries", expired_count))?;

        Ok(())
    }

    pub async fn update_credentials(&self, skip_validation: bool) -> Result<()> {
        let term = Term::stdout();

        term.write_line(&format!("🔑 {}", style("Update AWS Credentials").bold().blue()))?;
        term.write_line("")?;

        // Show current credential status if available
        if let Ok(Some(_)) = self.credential_manager.load_credentials().await {
            term.write_line("📋 Current credentials found. You can:")?;
            term.write_line("   • Update to new credentials")?;
            term.write_line("   • Keep existing if they're working")?;
            term.write_line("")?;
        }

        // Get new credentials
        term.write_line("🔐 Please provide your new AWS credentials:")?;
        let new_credentials = prompt_for_credentials().await?;

        // Validate credentials unless skipped
        if !skip_validation {
            term.write_line("🔍 Validating new credentials...")?;
            if !self.credential_manager.validate_credentials(&new_credentials).await? {
                return Err(TempS3Error::CredentialError(
                    "Invalid AWS credentials provided. Use --skip-validation to store anyway.".to_string(),
                ));
            }
            term.write_line(&format!("✅ {}", style("Credentials validated successfully").green()))?;
        } else {
            term.write_line(&format!("⚠️  {}", style("Skipping validation as requested").yellow()))?;
        }

        // Store new credentials
        self.credential_manager.store_credentials(&new_credentials).await?;
        term.write_line(&format!("✅ {}", style("Credentials updated and stored securely").green()))?;

        // Update application state
        if let Ok(mut state) = AppState::load().await {
            state.credentials_validated = !skip_validation;
            let _ = state.save().await; // Don't fail if state update fails
        }

        term.write_line("")?;
        term.write_line("💡 Next steps:")?;
        term.write_line("   • Test credentials: temps3 credentials test")?;
        term.write_line("   • Upload a file: temps3 upload <file_path>")?;

        Ok(())
    }

    pub async fn test_credentials(&self) -> Result<()> {
        let term = Term::stdout();

        term.write_line(&format!("🧪 {}", style("Test AWS Credentials").bold().blue()))?;
        term.write_line("")?;

        // Load credentials
        let credentials = match self.credential_manager.load_credentials().await? {
            Some(creds) => creds,
            None => {
                term.write_line("❌ No credentials found.")?;
                term.write_line("💡 Run 'temps3 credentials update' to set up credentials.")?;
                return Ok(());
            }
        };

        term.write_line("📋 Credential Information:")?;
        term.write_line(&format!("   🔑 Access Key: {}...{}", 
            &credentials.access_key_id[..4],
            &credentials.access_key_id[credentials.access_key_id.len()-4..]
        ))?;
        term.write_line(&format!("   🌍 Region: {}", credentials.region))?;
        if credentials.session_token.is_some() {
            term.write_line("   🎫 Session Token: Present")?;
        }
        term.write_line("")?;

        // Run comprehensive health check
        term.write_line("🔍 Running credential health check...")?;
        match self.credential_manager.credential_health_check(&self.config.bucket_name).await {
            Ok(status) => {
                if status.valid {
                    term.write_line(&format!("✅ {}", style("Credentials are valid and working").bold().green()))?;
                    
                    term.write_line("")?;
                    term.write_line("📊 Detailed Status:")?;
                    term.write_line(&format!("   🪣 Bucket Access: {}", 
                        if status.can_access_bucket { 
                            style("✅ Can access bucket").green() 
                        } else { 
                            style("⚠️  Bucket not found (will be created on first upload)").yellow() 
                        }
                    ))?;
                    term.write_line(&format!("   🔐 Permissions: {}", 
                        if status.has_required_permissions { 
                            style("✅ All required permissions available").green() 
                        } else { 
                            style("⚠️  Some permissions missing (may affect functionality)").yellow() 
                        }
                    ))?;
                } else {
                    term.write_line(&format!("❌ {}", style("Credential validation failed").bold().red()))?;
                    if let Some(error) = &status.error_message {
                        term.write_line(&format!("   📝 Error: {}", error))?;
                    }
                    if let Some(suggestion) = &status.suggestion {
                        term.write_line(&format!("   💡 Suggestion: {}", suggestion))?;
                    }
                    term.write_line("")?;
                    term.write_line("🔧 To fix this:")?;
                    term.write_line("   • Update credentials: temps3 credentials update")?;
                    term.write_line("   • Check AWS IAM permissions")?;
                    term.write_line("   • Verify AWS region settings")?;
                }
            }
            Err(e) => {
                term.write_line(&format!("❌ Failed to test credentials: {}", e))?;
                term.write_line("💡 Try updating your credentials: temps3 credentials update")?;
            }
        }

        Ok(())
    }

    pub async fn remove_credentials(&self, force: bool) -> Result<()> {
        let term = Term::stdout();

        term.write_line(&format!("🗑️  {}", style("Remove AWS Credentials").bold().red()))?;
        term.write_line("")?;

        // Check if credentials exist
        match self.credential_manager.load_credentials().await? {
            Some(_) => {
                term.write_line("📋 Current credentials found.")?;
            }
            None => {
                term.write_line("ℹ️  No credentials currently stored.")?;
                return Ok(());
            }
        }

        term.write_line("")?;
        term.write_line(&format!("⚠️  {}", style("WARNING: This will remove all stored AWS credentials!").bold().red()))?;
        term.write_line("   • You will need to set up credentials again")?;
        term.write_line("   • Existing upload URLs will remain valid until expiry")?;
        term.write_line("   • You won't be able to upload new files until credentials are restored")?;
        term.write_line("")?;

        // Confirmation unless force flag is used
        if !force {
            term.write_line("Type 'REMOVE' to confirm credential removal:")?;
            let input = self.read_user_confirmation().await?;
            
            if input != "REMOVE" {
                term.write_line("❌ Operation cancelled.")?;
                return Ok(());
            }
        }

        // Remove credentials
        term.write_line("🗑️  Removing stored credentials...")?;
        if let Err(e) = self.credential_manager.delete_credentials().await {
            term.write_line(&format!("⚠️  Warning: Failed to remove credentials: {}", e))?;
            term.write_line("   Credentials may still be stored")?;
        } else {
            term.write_line(&format!("✅ {}", style("Credentials removed successfully").green()))?;
        }

        // Update application state
        if let Ok(mut state) = AppState::load().await {
            state.credentials_validated = false;
            let _ = state.save().await; // Don't fail if state update fails
        }

        term.write_line("")?;
        term.write_line("💡 Next steps:")?;
        term.write_line("   • Set up new credentials: temps3 credentials update")?;
        term.write_line("   • Or run full initialization: temps3 init")?;

        Ok(())
    }

    async fn get_s3_service(&self) -> Result<&S3Service> {
        self.s3_service
            .as_ref()
            .ok_or_else(|| TempS3Error::ConfigError(
                "S3 service not initialized. Run 'temps3 init' first.".to_string(),
            ))
    }

    /// Async helper function to read user confirmation input without blocking the runtime
    async fn read_user_confirmation(&self) -> Result<String> {
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut input = String::new();
        
        reader.read_line(&mut input).await
            .map_err(|e| TempS3Error::FileSystemError(e))?;
        
        Ok(input.trim().to_string())
    }
}

fn format_file_size(bytes: i64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(500), "500.00 B");
        assert_eq!(format_file_size(1024), "1.00 KB");
        assert_eq!(format_file_size(1536), "1.50 KB");
        assert_eq!(format_file_size(1048576), "1.00 MB");
        assert_eq!(format_file_size(1073741824), "1.00 GB");
    }
}
