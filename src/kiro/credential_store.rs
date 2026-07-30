//! 凭据持久化适配层。
//!
//! 运行时仍由 MultiTokenManager 持有凭据和调度状态，本模块只负责持久化。
//! SQLite 使用 JSON payload 保存凭据，避免数据库 schema 跟随凭据字段频繁变化。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use parking_lot::Mutex;
use rusqlite::{Connection, params};

use crate::kiro::model::credentials::{CredentialsConfig, KiroCredentials};
use crate::model::config::CredentialStorageBackend;

#[derive(Clone)]
pub struct CredentialStore {
    backend: CredentialStoreBackend,
    legacy_path: PathBuf,
    cache_dir: Option<PathBuf>,
    file_write_lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
enum CredentialStoreBackend {
    File { multiple_format: bool },
    Sqlite { connection: Arc<Mutex<Connection>> },
}

impl CredentialStore {
    pub fn open(
        backend: CredentialStorageBackend,
        legacy_path: impl Into<PathBuf>,
        database_path: Option<&str>,
    ) -> anyhow::Result<(Arc<Self>, Vec<KiroCredentials>)> {
        let legacy_path = legacy_path.into();
        let cache_dir = legacy_path.parent().map(Path::to_path_buf);

        match backend {
            CredentialStorageBackend::File => {
                let config = CredentialsConfig::load(&legacy_path)?;
                let multiple_format = config.is_multiple();
                let credentials = config.into_sorted_credentials();
                Ok((
                    Arc::new(Self {
                        backend: CredentialStoreBackend::File { multiple_format },
                        legacy_path,
                        cache_dir,
                        file_write_lock: Arc::new(Mutex::new(())),
                    }),
                    credentials,
                ))
            }
            CredentialStorageBackend::Sqlite => {
                let path = resolve_database_path(&legacy_path, database_path);
                let connection = Connection::open(&path)
                    .with_context(|| format!("打开 SQLite 凭据数据库失败: {}", path.display()))?;
                connection
                    .busy_timeout(std::time::Duration::from_secs(5))
                    .context("设置 SQLite busy_timeout 失败")?;
                connection
                    .execute_batch(
                        r#"
                        PRAGMA journal_mode = WAL;
                        PRAGMA synchronous = NORMAL;
                        CREATE TABLE IF NOT EXISTS credentials (
                            id INTEGER PRIMARY KEY,
                            payload TEXT NOT NULL,
                            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                        );
                        "#,
                    )
                    .context("初始化 SQLite 凭据表失败")?;

                let store = Arc::new(Self {
                    backend: CredentialStoreBackend::Sqlite {
                        connection: Arc::new(Mutex::new(connection)),
                    },
                    legacy_path,
                    cache_dir: path.parent().map(Path::to_path_buf),
                    file_write_lock: Arc::new(Mutex::new(())),
                });

                let mut credentials = store.load_sqlite()?;
                if credentials.is_empty() {
                    let legacy_config = CredentialsConfig::load(&store.legacy_path)?;
                    let legacy_credentials = legacy_config.into_sorted_credentials();
                    if !legacy_credentials.is_empty() {
                        credentials = legacy_credentials;
                        store.replace_all(&mut credentials)?;
                        tracing::info!(
                            "SQLite 凭据库为空，已从 {} 导入 {} 个凭据",
                            store.legacy_path.display(),
                            credentials.len()
                        );
                    }
                }

                Ok((store, credentials))
            }
        }
    }

    pub fn file(path: PathBuf, multiple_format: bool) -> Arc<Self> {
        Arc::new(Self {
            cache_dir: path.parent().map(Path::to_path_buf),
            legacy_path: path,
            backend: CredentialStoreBackend::File { multiple_format },
            file_write_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn save_all(&self, credentials: &[KiroCredentials]) -> anyhow::Result<bool> {
        match &self.backend {
            CredentialStoreBackend::File { .. } => self.save_file(credentials),
            CredentialStoreBackend::Sqlite { .. } => {
                let mut credentials = credentials.to_vec();
                self.replace_all(&mut credentials)?;
                tracing::debug!("已写入 SQLite 凭据库: {} 条", credentials.len());
                Ok(true)
            }
        }
    }

    pub fn cache_dir(&self) -> Option<PathBuf> {
        self.cache_dir.clone()
    }

    pub fn backend_name(&self) -> &'static str {
        match &self.backend {
            CredentialStoreBackend::File { .. } => "file",
            CredentialStoreBackend::Sqlite { .. } => "sqlite",
        }
    }

    fn load_sqlite(&self) -> anyhow::Result<Vec<KiroCredentials>> {
        let CredentialStoreBackend::Sqlite { connection, .. } = &self.backend else {
            bail!("当前凭据存储不是 SQLite");
        };

        let connection = connection.lock();
        let mut statement = connection
            .prepare("SELECT id, payload FROM credentials ORDER BY id")
            .context("读取 SQLite 凭据失败")?;
        let rows = statement
            .query_map([], |row| {
                let id: u64 = row.get(0)?;
                let payload: String = row.get(1)?;
                Ok((id, payload))
            })
            .context("查询 SQLite 凭据失败")?;

        let mut credentials = Vec::new();
        for row in rows {
            let (id, payload) = row.context("读取 SQLite 凭据行失败")?;
            let mut credential: KiroCredentials =
                serde_json::from_str(&payload).context("解析 SQLite 凭据 payload 失败")?;
            credential.id = Some(id);
            credential.canonicalize_auth_method();
            credentials.push(credential);
        }
        credentials.sort_by_key(|credential| (credential.priority, credential.id.unwrap_or(0)));
        Ok(credentials)
    }

    fn replace_all(&self, credentials: &mut [KiroCredentials]) -> anyhow::Result<()> {
        let CredentialStoreBackend::Sqlite { connection, .. } = &self.backend else {
            self.save_file(credentials)?;
            return Ok(());
        };

        let mut used_ids = HashSet::new();
        let mut next_id = credentials
            .iter()
            .filter_map(|credential| credential.id)
            .max()
            .unwrap_or(0)
            + 1;
        for credential in credentials.iter_mut() {
            let id = match credential.id {
                Some(id) => id,
                None => {
                    while used_ids.contains(&next_id) {
                        next_id += 1;
                    }
                    let id = next_id;
                    next_id += 1;
                    credential.id = Some(id);
                    id
                }
            };
            if !used_ids.insert(id) {
                bail!("检测到重复的凭据 ID: {}", id);
            }
            credential.canonicalize_auth_method();
        }

        let mut connection = connection.lock();
        let transaction = connection
            .transaction()
            .context("开启 SQLite 凭据事务失败")?;
        transaction
            .execute("DELETE FROM credentials", [])
            .context("清理 SQLite 凭据失败")?;

        for credential in credentials.iter() {
            let id = credential.id.context("SQLite 凭据缺少 ID")?;
            let payload = serde_json::to_string(credential).context("序列化 SQLite 凭据失败")?;
            transaction
                .execute(
                    "INSERT INTO credentials (id, payload) VALUES (?1, ?2)",
                    params![id, payload],
                )
                .with_context(|| format!("写入 SQLite 凭据失败: {}", id))?;
        }

        transaction.commit().context("提交 SQLite 凭据事务失败")?;
        Ok(())
    }

    fn save_file(&self, credentials: &[KiroCredentials]) -> anyhow::Result<bool> {
        let CredentialStoreBackend::File { multiple_format } = &self.backend else {
            return Ok(false);
        };
        if !multiple_format {
            return Ok(false);
        }

        let _guard = self.file_write_lock.lock();
        let json = serde_json::to_string_pretty(credentials).context("序列化凭据失败")?;
        std::fs::write(&self.legacy_path, json)
            .with_context(|| format!("回写凭据文件失败: {:?}", self.legacy_path))?;
        Ok(true)
    }
}

fn resolve_database_path(legacy_path: &Path, configured_path: Option<&str>) -> PathBuf {
    let default_path = || {
        legacy_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("credentials.sqlite3")
    };

    let Some(configured_path) = configured_path
        .map(str::trim)
        .filter(|path| !path.is_empty())
    else {
        return default_path();
    };

    let path = PathBuf::from(configured_path);
    if path.is_absolute() {
        path
    } else {
        legacy_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn sqlite_store_migrates_legacy_credentials_and_keeps_ids() {
        let dir = tempdir().unwrap();
        let credentials_path = dir.path().join("credentials.json");
        let database_path = dir.path().join("credentials.sqlite3");
        let mut credential = KiroCredentials::default();
        credential.refresh_token = Some("refresh-token".to_string());
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential]).unwrap(),
        )
        .unwrap();

        let (store, loaded) = CredentialStore::open(
            CredentialStorageBackend::Sqlite,
            &credentials_path,
            Some(database_path.to_str().unwrap()),
        )
        .unwrap();

        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].id.is_some());
        assert_eq!(store.backend_name(), "sqlite");
        assert!(database_path.exists());
    }
}
