use std::fs;
use std::path::Path;

use crate::types::BenchResult;

pub struct CsvReporter {
    writer: csv::Writer<std::fs::File>,
}

impl CsvReporter {
    pub fn new(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = std::fs::File::create(path)?;
        let mut reporter = Self {
            writer: csv::Writer::from_writer(file),
        };
        reporter
            .writer
            .write_record([
                "algorithm",
                "param_set",
                "keygen_median_ns",
                "sign_median_ns",
                "verify_median_ns",
                "public_key_bytes",
                "secret_key_bytes",
                "signature_bytes",
            ])
            .map_err(std::io::Error::other)?;
        reporter.writer.flush()?;
        Ok(reporter)
    }

    pub fn write_result(&mut self, result: &BenchResult) -> csv::Result<()> {
        self.writer.write_record([
            result.algorithm.as_str(),
            result.param_set.as_str(),
            &result.keygen_median_ns.to_string(),
            &result.sign_median_ns.to_string(),
            &result.verify_median_ns.to_string(),
            &result.sizes.public_key_bytes.to_string(),
            &result.sizes.secret_key_bytes.to_string(),
            &result.sizes.signature_bytes.to_string(),
        ])?;
        self.writer.flush()?;
        Ok(())
    }
}
