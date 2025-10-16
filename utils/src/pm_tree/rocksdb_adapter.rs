use std::{
    collections::HashMap,
    sync::Arc,
};
use std::path::PathBuf;
use pmtree::{DBKey, Database, DatabaseErrorKind, PmtreeErrorKind, PmtreeResult, TreeErrorKind, Value};
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, Options, ReadOptions, WriteBatch, WriteBatchWithIndex,
};

#[derive(Default)]
pub struct RocksDbWrapperConfig {
    options: Options,
    db_path: PathBuf,
    cfs: Vec<ColumnFamilyDescriptor>,
    // TODO: ColumnFamily for type? but no default?
    cf_tree: String,
}

pub struct RocksDbWrapper {
    db: Arc<DB>,
    config: RocksDbWrapperConfig
}

impl RocksDbWrapper {
    fn new_with_db(db: Arc<DB>, config: RocksDbWrapperConfig) -> PmtreeResult<Self> {
        Ok(RocksDbWrapper {
            db,
            config,
        })
    }
}

impl Database for RocksDbWrapper {

    type Config = RocksDbWrapperConfig;

    fn new(mut config: Self::Config) -> PmtreeResult<Self>
    where
        Self: Sized
    {
        let cfs = std::mem::take(&mut config.cfs);

        let db = DB::open_cf_descriptors(
            &config.options,
            &config.db_path,
            cfs
        ).map_err(|e|
            PmtreeErrorKind::DatabaseError(DatabaseErrorKind::CustomError(e.to_string()))
        )?;

        Ok(Self {
            db: Arc::new(db),
            config
        })
    }

    fn load(config: Self::Config) -> PmtreeResult<Self>
    where
        Self: Sized
    {
        // FIXME
        // Self::new(config)
        unimplemented!()
    }

    fn get(&self, key: DBKey) -> PmtreeResult<Option<Value>> {
        // Unwrap safe - assume the db is created with this column family
        let cf = self.db.cf_handle(self.config.cf_tree.as_str()).unwrap();
        match self.db.get_cf(cf, key.as_slice()) {
            Ok(value) => Ok(value),
            Err(_e) => Err(PmtreeErrorKind::TreeError(TreeErrorKind::InvalidKey))
        }
    }

    fn put(&mut self, key: DBKey, value: Value) -> PmtreeResult<()> {
        // Unwrap safe - assume the db is created with this column family
        let cf = self.db.cf_handle(self.config.cf_tree.as_str()).unwrap();
        match self.db.put_cf(cf, key.as_slice(), value.as_slice()) {
            Ok(_) => Ok(()),
            Err(_e) => Err(PmtreeErrorKind::TreeError(TreeErrorKind::InvalidKey))
        }
    }

    fn put_batch(&mut self, subtree: HashMap<DBKey, Value>) -> PmtreeResult<()> {
        // Unwrap safe - assume the db is created with this column family
        let cf = self.db.cf_handle(self.config.cf_tree.as_str()).unwrap();
        let mut batch = WriteBatch::new();

        for (key, value) in subtree {
            batch.put_cf(cf, key.as_slice(), value.as_slice());
        }

        self
            .db
            .write(batch)
            .map_err(|_| PmtreeErrorKind::TreeError(TreeErrorKind::InvalidKey))?
            ;

        Ok(())
    }

    fn close(&mut self) -> PmtreeResult<()> {

        // Unwrap safe - assume the db is created with this column family
        let cf = self.db.cf_handle(self.config.cf_tree.as_str()).unwrap();
        self
            .db
            .flush_cf(cf)
            .map_err(|e| PmtreeErrorKind::DatabaseError(DatabaseErrorKind::CustomError(
                e.to_string()
            )))? ;
        Ok(())
    }

}