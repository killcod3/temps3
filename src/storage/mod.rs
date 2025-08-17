use crate::error::{Result, TempS3Error};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UploadRecord {
    pub id: String,
    pub file_name: String,
    pub file_path: String,
    pub file_size: i64,
    pub s3_key: String,
    pub bucket_name: String,
    pub ttl_tag: String,
    pub presigned_url: String,
    pub url_expiry: DateTime<Utc>,
    pub upload_date: DateTime<Utc>,
    pub checksum: String,
}

impl UploadRecord {
    pub fn new(
        file_name: String,
        file_path: String,
        file_size: i64,
        s3_key: String,
        bucket_name: String,
        ttl_tag: String,
        presigned_url: String,
        url_expiry: DateTime<Utc>,
        checksum: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            file_name,
            file_path,
            file_size,
            s3_key,
            bucket_name,
            ttl_tag,
            presigned_url,
            url_expiry,
            upload_date: Utc::now(),
            checksum,
        }
    }
}

pub struct StorageManager {
    pool: SqlitePool,
}

impl StorageManager {
    pub async fn new(database_path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = database_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| TempS3Error::DatabaseError(sqlx::Error::Io(e)))?;
        }

        // Use connection options to ensure the database file is created
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(database_path)
                    .create_if_missing(true)
            )
            .await?;

        let manager = Self { pool };
        manager.initialize_schema().await?;

        Ok(manager)
    }

    async fn initialize_schema(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS uploads (
                id TEXT PRIMARY KEY,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                s3_key TEXT NOT NULL,
                bucket_name TEXT NOT NULL,
                ttl_tag TEXT NOT NULL,
                presigned_url TEXT NOT NULL,
                url_expiry TEXT NOT NULL,
                upload_date TEXT NOT NULL,
                checksum TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indices for better performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_upload_date ON uploads(upload_date)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_file_name ON uploads(file_name)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_s3_key ON uploads(s3_key)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn store_upload(&self, record: &UploadRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO uploads (
                id, file_name, file_path, file_size, s3_key, bucket_name,
                ttl_tag, presigned_url, url_expiry, upload_date, checksum
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.id)
        .bind(&record.file_name)
        .bind(&record.file_path)
        .bind(record.file_size)
        .bind(&record.s3_key)
        .bind(&record.bucket_name)
        .bind(&record.ttl_tag)
        .bind(&record.presigned_url)
        .bind(record.url_expiry.to_rfc3339())
        .bind(record.upload_date.to_rfc3339())
        .bind(&record.checksum)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Advanced list method with filtering, pagination, and sorting
    pub async fn list_uploads_advanced(
        &self,
        ttl_filter: Option<&str>,
        status_filter: &str,
        limit: u32,
        page: u32,
        sort_by: &str,
        order: &str,
        search_pattern: Option<&str>,
    ) -> Result<(Vec<UploadRecord>, u64)> {
        let offset = (page - 1) * limit;
        let now = Utc::now().to_rfc3339();
        
        // Build the WHERE clause
        let mut where_conditions = Vec::new();
        let mut bind_values: Vec<String> = Vec::new();
        
        // TTL filter
        if let Some(ttl) = ttl_filter {
            where_conditions.push("ttl_tag = ?");
            bind_values.push(ttl.to_string());
        }
        
        // Status filter
        match status_filter {
            "active" => {
                where_conditions.push("url_expiry > ?");
                bind_values.push(now.clone());
            }
            "expired" => {
                where_conditions.push("url_expiry <= ?");
                bind_values.push(now.clone());
            }
            _ => {} // "all" - no filter
        }
        
        // Search pattern
        if let Some(pattern) = search_pattern {
            where_conditions.push("file_name LIKE ?");
            bind_values.push(format!("%{}%", pattern));
        }
        
        // Build WHERE clause
        let where_clause = if where_conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_conditions.join(" AND "))
        };
        
        // Build ORDER BY clause
        let order_by = match sort_by {
            "size" => "file_size",
            "name" => "file_name",
            "expiry" => "url_expiry",
            _ => "upload_date", // default to date
        };
        
        let order_direction = if order == "asc" { "ASC" } else { "DESC" };
        
        // Count total records (for pagination info)
        let count_query = format!("SELECT COUNT(*) as count FROM uploads {}", where_clause);
        let mut count_query_builder = sqlx::query(&count_query);
        for value in &bind_values {
            count_query_builder = count_query_builder.bind(value);
        }
        let count_row = count_query_builder.fetch_one(&self.pool).await?;
        let total_count: i64 = count_row.get("count");
        
        // Get records with pagination
        let records_query = format!(
            "SELECT * FROM uploads {} ORDER BY {} {} LIMIT ? OFFSET ?",
            where_clause, order_by, order_direction
        );
        
        let mut query_builder = sqlx::query(&records_query);
        for value in &bind_values {
            query_builder = query_builder.bind(value);
        }
        query_builder = query_builder.bind(limit as i64).bind(offset as i64);
        
        let rows = query_builder.fetch_all(&self.pool).await?;
        
        let mut records = Vec::new();
        for row in rows {
            records.push(self.row_to_upload_record(row)?);
        }
        
        Ok((records, total_count as u64))
    }

    /// Purge all entries from the database
    pub async fn purge_all_uploads(&self) -> Result<i64> {
        let rows_affected = sqlx::query("DELETE FROM uploads")
            .execute(&self.pool)
            .await?
            .rows_affected();

        Ok(rows_affected as i64)
    }

    /// Mark all entries as expired by setting url_expiry to current time
    pub async fn expire_all_uploads(&self) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        
        let rows_affected = sqlx::query(
            "UPDATE uploads SET url_expiry = ? WHERE url_expiry > ?"
        )
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok(rows_affected as i64)
    }

    /// Get count of all uploads
    pub async fn count_all_uploads(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM uploads")
            .fetch_one(&self.pool)
            .await?;

        Ok(row.get::<i64, _>("count"))
    }

    /// Get count of active uploads (non-expired)
    pub async fn count_active_uploads(&self) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        
        let row = sqlx::query("SELECT COUNT(*) as count FROM uploads WHERE url_expiry > ?")
            .bind(now)
            .fetch_one(&self.pool)
            .await?;

        Ok(row.get::<i64, _>("count"))
    }

    fn row_to_upload_record(&self, row: sqlx::sqlite::SqliteRow) -> Result<UploadRecord> {
        let url_expiry_str: String = row.try_get("url_expiry")?;
        let upload_date_str: String = row.try_get("upload_date")?;

        let url_expiry = DateTime::parse_from_rfc3339(&url_expiry_str)
            .map_err(|e| TempS3Error::DatabaseError(sqlx::Error::Decode(Box::new(e))))?
            .with_timezone(&Utc);

        let upload_date = DateTime::parse_from_rfc3339(&upload_date_str)
            .map_err(|e| TempS3Error::DatabaseError(sqlx::Error::Decode(Box::new(e))))?
            .with_timezone(&Utc);

        Ok(UploadRecord {
            id: row.try_get("id")?,
            file_name: row.try_get("file_name")?,
            file_path: row.try_get("file_path")?,
            file_size: row.try_get("file_size")?,
            s3_key: row.try_get("s3_key")?,
            bucket_name: row.try_get("bucket_name")?,
            ttl_tag: row.try_get("ttl_tag")?,
            presigned_url: row.try_get("presigned_url")?,
            url_expiry,
            upload_date,
            checksum: row.try_get("checksum")?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadStats {
    pub total_uploads: i64,
    pub total_size_bytes: i64,
    pub average_size_bytes: i64,
    pub ttl_distribution: std::collections::HashMap<String, i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_storage_manager_operations() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        
        let storage = StorageManager::new(&db_path).await.unwrap();
        
        let record = UploadRecord::new(
            "test.txt".to_string(),
            "/path/to/test.txt".to_string(),
            1024,
            "test-key".to_string(),
            "test-bucket".to_string(),
            "3d".to_string(),
            "https://example.com/presigned".to_string(),
            Utc::now() + chrono::Duration::days(7),
            "sha256checksum".to_string(),
        );

        // Test store
        storage.store_upload(&record).await.unwrap();

        // Test list with advanced method
        let (uploads, total_count) = storage.list_uploads_advanced(
            None, "all", 10, 1, "date", "desc", None
        ).await.unwrap();
        assert_eq!(uploads.len(), 1);
        assert_eq!(total_count, 1);

        // Test count methods
        let total_uploads = storage.count_all_uploads().await.unwrap();
        assert_eq!(total_uploads, 1);
        
        let active_uploads = storage.count_active_uploads().await.unwrap();
        assert_eq!(active_uploads, 1);
    }
}
