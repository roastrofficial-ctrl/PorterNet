use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use serde::Serialize;
use uuid::Uuid;

use crate::{canonical, Result};

pub fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| crate::Error::Invalid("fact path has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("fact"),
        Uuid::new_v4().simple()
    ));
    let result = (|| {
        let mut stream = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        stream.write_all(&canonical::bytes(value)?)?;
        stream.write_all(b"\n")?;
        stream.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
