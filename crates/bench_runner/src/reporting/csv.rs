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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BenchResult, SizeMetrics};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_csv_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "bench_runner_csv_{}_{}.csv",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ))
    }

    #[test]
    fn csv_reporter_writes_header_and_result_rows() {
        let path = temp_csv_path();
        let mut reporter =
            CsvReporter::new(&path).expect("csv reporter should initialize");

        reporter
            .write_result(&BenchResult {
                algorithm: "Mock".to_string(),
                param_set: "Mock-1".to_string(),
                keygen_median_ns: 10,
                sign_median_ns: 20,
                verify_median_ns: 30,
                sizes: SizeMetrics::new(40, 50, 60),
            })
            .expect("csv row should be written");

        let contents = std::fs::read_to_string(&path)
            .expect("csv file should be readable");

        assert_eq!(
            contents,
            concat!(
                "algorithm,param_set,keygen_median_ns,sign_median_ns,verify_median_ns,public_key_bytes,secret_key_bytes,signature_bytes\n",
                "Mock,Mock-1,10,20,30,40,50,60\n"
            )
        );

        let _ = std::fs::remove_file(path);
    }
}
