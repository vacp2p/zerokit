use pmtree::*;

use sled::Db as Sled;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

pub struct SledDB(Sled);

impl SledDB {
    fn new_with_tries(config: <SledDB as Database>::Config, tries: u32) -> PmtreeResult<Self> {
        // If we've tried more than 10 times, we give up and return an error.
        if tries >= 10 {
            return Err(PmtreeErrorKind::DatabaseError(
                DatabaseErrorKind::CustomError(format!(
                    "Cannot create database: exceeded maximum retry attempts. {config:#?}"
                )),
            ));
        }
        match config.open() {
            Ok(db) => Ok(SledDB(db)),
            Err(err) if err.to_string().contains("WouldBlock") => {
                // try till the fd is freed
                // sleep for 10^tries milliseconds, then recursively try again
                thread::sleep(Duration::from_millis(10u64.pow(tries)));
                Self::new_with_tries(config, tries + 1)
            }
            Err(err) => {
                // On any other error, we return immediately.
                Err(PmtreeErrorKind::DatabaseError(
                    DatabaseErrorKind::CustomError(format!(
                        "Cannot create database: {err} {config:#?}"
                    )),
                ))
            }
        }
    }
}

impl Database for SledDB {
    type Config = sled::Config;

    fn new(config: Self::Config) -> PmtreeResult<Self> {
        let db = Self::new_with_tries(config, 0)?;
        Ok(db)
    }

    fn load(config: Self::Config) -> PmtreeResult<Self> {
        let db = match config.open() {
            Ok(db) => db,
            Err(err) => {
                return Err(PmtreeErrorKind::DatabaseError(
                    DatabaseErrorKind::CustomError(format!("Cannot load database: {err}")),
                ))
            }
        };

        if !db.was_recovered() {
            return Err(PmtreeErrorKind::DatabaseError(
                DatabaseErrorKind::CustomError(format!(
                    "Database was not recovered: {}",
                    config.path.display()
                )),
            ));
        }

        Ok(SledDB(db))
    }

    fn close(&mut self) -> PmtreeResult<()> {
        let _ = self.0.flush().map_err(|_| {
            PmtreeErrorKind::DatabaseError(DatabaseErrorKind::CustomError(
                "Cannot flush database".to_string(),
            ))
        })?;
        Ok(())
    }

    fn get(&self, key: DBKey) -> PmtreeResult<Option<Value>> {
        match self.0.get(key) {
            Ok(value) => Ok(value.map(|val| val.to_vec())),
            Err(_e) => Err(PmtreeErrorKind::TreeError(TreeErrorKind::InvalidKey)),
        }
    }

    fn put(&mut self, key: DBKey, value: Value) -> PmtreeResult<()> {
        match self.0.insert(key, value) {
            Ok(_) => Ok(()),
            Err(_e) => Err(PmtreeErrorKind::TreeError(TreeErrorKind::InvalidKey)),
        }
    }

    fn put_batch(&mut self, subtree: HashMap<DBKey, Value>) -> PmtreeResult<()> {
        let mut batch = sled::Batch::default();

        for (key, value) in subtree {
            batch.insert(&key, value);
        }

        self.0
            .apply_batch(batch)
            .map_err(|_| PmtreeErrorKind::TreeError(TreeErrorKind::InvalidKey))?;
        Ok(())
    }
}
