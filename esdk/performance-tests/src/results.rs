// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::alloc;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize, Clone)]
pub struct BenchmarkResult {
    pub test_name: String,
    pub language: String,
    pub data_size: usize,
    pub concurrency: usize,
    pub encrypt_latency_ms: f64,
    pub decrypt_latency_ms: f64,
    pub end_to_end_latency_ms: f64,
    pub ops_per_second: f64,
    pub bytes_per_second: f64,
    pub peak_memory_mb: f64,
    pub memory_efficiency_ratio: f64,
    pub p50_latency: f64,
    pub p95_latency: f64,
    pub p99_latency: f64,
    pub timestamp: String,
    pub rust_version: String,
    pub cpu_count: usize,
    pub total_memory_gb: f64,
    pub alloc: alloc::ResourceResults,
}

#[derive(Debug, Serialize)]
struct BenchmarkResults {
    metadata: BenchmarkMetadata,
    results: Vec<BenchmarkResult>,
}

#[derive(Debug, Serialize)]
struct BenchmarkMetadata {
    language: String,
    // Identifies which keyring produced these results so a dashboard can plot
    // this series separately from other keyrings.
    keyring: String,
    timestamp: String,
    rust_version: String,
    cpu_count: usize,
    total_memory_gb: f64,
    total_tests: usize,
}

pub fn average(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

pub fn percentile(sorted_values: &[f64], p: f64) -> f64 {
    if sorted_values.is_empty() {
        return 0.0;
    }
    if p <= 0.0 {
        return sorted_values[0];
    }
    if p >= 100.0 {
        return sorted_values[sorted_values.len() - 1];
    }

    let index = (p / 100.0) * (sorted_values.len() - 1) as f64;
    let lower = index.floor() as usize;
    let upper = index.ceil() as usize;

    if lower == upper {
        return sorted_values[lower];
    }

    let weight = index - lower as f64;
    sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight
}

pub fn save_results(
    results: &[BenchmarkResult],
    output_path: &str,
    keyring: &str,
    cpu_count: usize,
    total_memory_gb: f64,
) -> Result<()> {
    if let Some(parent) = Path::new(output_path).parent() {
        fs::create_dir_all(parent)?;
    }

    let results_data = BenchmarkResults {
        metadata: BenchmarkMetadata {
            language: "rust".to_string(),
            keyring: keyring.to_string(),
            timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            rust_version: env!("RUSTC_VERSION").to_string(),
            cpu_count,
            total_memory_gb,
            total_tests: results.len(),
        },
        results: results.to_vec(),
    };

    let json_data = serde_json::to_string_pretty(&results_data)?;
    let mut file = File::create(output_path)?;
    file.write_all(json_data.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{average, percentile};

    #[test]
    fn average_of_empty_is_zero() {
        assert_eq!(average(&[]), 0.0);
    }

    #[test]
    fn average_computes_mean() {
        assert_eq!(average(&[2.0, 4.0, 6.0]), 4.0);
    }

    #[test]
    fn percentile_of_empty_is_zero() {
        assert_eq!(percentile(&[], 50.0), 0.0);
    }

    #[test]
    fn percentile_clamps_to_bounds() {
        let sorted = [10.0, 20.0, 30.0];
        assert_eq!(percentile(&sorted, 0.0), 10.0);
        assert_eq!(percentile(&sorted, 100.0), 30.0);
    }

    #[test]
    fn percentile_on_sample_boundaries() {
        let sorted = [0.0, 10.0, 20.0, 30.0, 40.0];
        assert_eq!(percentile(&sorted, 25.0), 10.0);
        assert_eq!(percentile(&sorted, 50.0), 20.0);
        assert_eq!(percentile(&sorted, 75.0), 30.0);
    }

    #[test]
    fn percentile_interpolates_between_samples() {
        assert_eq!(percentile(&[10.0, 20.0], 50.0), 15.0);
    }
}
