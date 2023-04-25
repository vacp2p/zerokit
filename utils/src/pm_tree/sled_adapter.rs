use pmtree::*;

use sled::Db as Sled;
use std::collections::HashMap;

pub struct SledDB(Sled);

impl Database for SledDB {
    type Config = sled::Config;

    fn new(config: Self::Config) -> PmtreeResult<Self> {
        let db: Sled = match config.open() {
            Ok(db) => db,
            Err(e) => {
                return Err(PmtreeErrorKind::DatabaseError(
                    DatabaseErrorKind::CustomError(format!(
                        "Cannot create database: {} {:#?}",
                        e, config
                    )),
                ))
            }
        };

        Ok(SledDB(db))
    }

    fn load(config: Self::Config) -> PmtreeResult<Self> {
        let db: Sled = match sled::open(&config.path) {
            Ok(db) => db,
            Err(e) => {
                return Err(PmtreeErrorKind::DatabaseError(
                    DatabaseErrorKind::CustomError(format!("Cannot load database: {}", e)),
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
