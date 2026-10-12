// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::alloc;
use anyhow::Result;
use aws_crypto_mpl::SharedKeyring;
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, Esdk};
use chrono::Utc;
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};
use log::{info, warn};
use memory_stats::memory_stats;
use rand::Rng;
use std::time::Instant;

use crate::benchmark::{EsdkBenchmark, MEMORY_TEST_ITERATIONS};
use crate::results::{BenchmarkResult, average, percentile};

impl EsdkBenchmark {
    fn benchmark_encryption_context(data_len: usize) -> EncryptionContext {
        let mut ec = EncryptionContext::new();
        ec.insert("purpose".to_string(), "performance-test".to_string());
        ec.insert("size".to_string(), data_len.to_string());
        ec
    }

    /// Runs one encrypt+decrypt cycle and returns (encrypt_ms, decrypt_ms).
    async fn encrypt_decrypt(
        esdk_client: &Esdk,
        keyring: &SharedKeyring,
        data: &[u8],
    ) -> Result<(f64, f64)> {
        let encrypt_input = EncryptInput::builder()
            .plaintext(data)
            .encryption_context(Self::benchmark_encryption_context(data.len()))
            .keyring(keyring.clone())
            .build()
            .map_err(|e| anyhow::anyhow!("invalid encrypt input: {e}"))?;

        let encrypt_start = Instant::now();
        let encrypt_output = esdk_client
            .encrypt(&encrypt_input)
            .await
            .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?;
        let encrypt_duration = encrypt_start.elapsed().as_secs_f64() * 1000.0;

        let ciphertext = encrypt_output.ciphertext;

        let decrypt_input = DecryptInput::builder()
            .ciphertext(&ciphertext)
            .keyring(keyring.clone())
            .build()
            .map_err(|e| anyhow::anyhow!("invalid decrypt input: {e}"))?;

        let decrypt_start = Instant::now();
        let decrypt_output = esdk_client
            .decrypt(&decrypt_input)
            .await
            .map_err(|e| anyhow::anyhow!("decrypt failed: {e}"))?;
        let decrypt_duration = decrypt_start.elapsed().as_secs_f64() * 1000.0;

        if data != decrypt_output.plaintext.as_slice() {
            return Err(anyhow::anyhow!("data integrity check failed"));
        }

        Ok((encrypt_duration, decrypt_duration))
    }

    fn should_run_test_type(&self, test_type: &str, is_quick_mode: bool) -> bool {
        if is_quick_mode
            && let Some(quick_config) = &self.config.quick_config
            && !quick_config.test_types.is_empty()
        {
            return quick_config.test_types.contains(&test_type.to_string());
        }
        true
    }

    /// Runs throughput test measuring operations per second and data processing rate
    async fn run_throughput_test(
        &mut self,
        data_size: usize,
        iterations: usize,
    ) -> Result<BenchmarkResult> {
        info!(
            "Running throughput test - Size: {} bytes, Iterations: {}",
            data_size, iterations
        );

        // Boxed: 50 MiB on the stack would overflow.
        let data = {
            let mut data = vec![0u8; data_size];
            rand::rng().fill(&mut data[..]);
            data.into_boxed_slice()
        };

        // Warmup (for the hierarchical keyring, also primes its branch-key cache)
        for i in 0..self.config.iterations.warmup {
            if let Err(e) = Self::encrypt_decrypt(&self.esdk_client, &self.keyring, &data).await {
                return Err(anyhow::anyhow!("Warmup iteration {} failed: {}", i, e));
            }
        }

        let mut encrypt_latencies = Vec::new();
        let mut decrypt_latencies = Vec::new();
        let mut end_to_end_latencies = Vec::new();
        let mut total_bytes = 0u64;

        let pb = ProgressBar::new(iterations as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg} {percent}% |{bar:50.cyan/blue}| ({pos}/{len}) [{elapsed}<{eta}]")
                .unwrap()
                .progress_chars("██ "),
        );
        pb.set_message("Throughput test");

        let start_time = Instant::now();
        let alloc = alloc::ResourceTracker::new();
        for i in 0..iterations {
            let iteration_start = Instant::now();
            let (encrypt_ms, decrypt_ms) =
                Self::encrypt_decrypt(&self.esdk_client, &self.keyring, &data)
                    .await
                    .map_err(|e| anyhow::anyhow!("Measurement iteration {} failed: {}", i, e))?;
            let iteration_duration = iteration_start.elapsed().as_secs_f64() * 1000.0;

            encrypt_latencies.push(encrypt_ms);
            decrypt_latencies.push(decrypt_ms);
            end_to_end_latencies.push(iteration_duration);
            total_bytes += data_size as u64;

            pb.inc(1);
        }
        let total_duration = start_time.elapsed().as_secs_f64();
        pb.finish_and_clear();

        end_to_end_latencies.sort_by(|a, b| a.total_cmp(b));
        let result = BenchmarkResult {
            test_name: "throughput".to_string(),
            language: "rust".to_string(),
            data_size,
            concurrency: 1,
            encrypt_latency_ms: average(&encrypt_latencies),
            decrypt_latency_ms: average(&decrypt_latencies),
            end_to_end_latency_ms: average(&end_to_end_latencies),
            ops_per_second: iterations as f64 / total_duration,
            bytes_per_second: total_bytes as f64 / total_duration,
            p50_latency: percentile(&end_to_end_latencies, 50.0),
            p95_latency: percentile(&end_to_end_latencies, 95.0),
            p99_latency: percentile(&end_to_end_latencies, 99.0),
            peak_memory_mb: 0.0,
            memory_efficiency_ratio: 0.0,
            timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            rust_version: env!("RUSTC_VERSION").to_string(),
            cpu_count: self.cpu_count,
            total_memory_gb: self.total_memory_gb,
            alloc: alloc.get_results(),
        };

        info!(
            "Throughput test completed - Ops/sec: {:.2}, MB/sec: {:.2}",
            result.ops_per_second,
            result.bytes_per_second / (1024.0 * 1024.0)
        );

        Ok(result)
    }

    /// Runs memory usage test by measuring memory delta during ESDK operations
    async fn run_memory_test(&mut self, data_size: usize) -> Result<BenchmarkResult> {
        info!(
            "Running memory test - Size: {} bytes ({} iterations)",
            data_size, MEMORY_TEST_ITERATIONS
        );

        // Boxed: 50 MiB on the stack would overflow.
        let data = {
            let mut data = vec![0u8; data_size];
            rand::rng().fill(&mut data[..]);
            data.into_boxed_slice()
        };

        let mut peak_memory_delta_mb = 0.0;
        let mut avg_memory_samples = Vec::new();
        let alloc = alloc::ResourceTracker::new();

        for i in 0..MEMORY_TEST_ITERATIONS {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            let baseline_memory = if let Some(stats) = memory_stats() {
                stats.physical_mem as f64 / (1024.0 * 1024.0)
            } else {
                0.0
            };

            let mut iteration_samples = Vec::new();
            let mut iteration_peak = baseline_memory;

            let operation_start = Instant::now();

            let data_clone = data.clone();
            let esdk_client = self.esdk_client;
            let keyring = self.keyring.clone();

            let operation_task = tokio::spawn(async move {
                Self::encrypt_decrypt(&esdk_client, &keyring, &data_clone).await
            });

            let mut sample_count = 0;
            while !operation_task.is_finished() {
                if let Some(stats) = memory_stats() {
                    let current_physical = stats.physical_mem as f64 / (1024.0 * 1024.0);
                    let delta = current_physical - baseline_memory;

                    if delta > 0.0 {
                        iteration_samples.push(delta);
                    }
                    if current_physical > iteration_peak {
                        iteration_peak = current_physical;
                    }
                    sample_count += 1;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }

            operation_task.await??;
            let operation_duration = operation_start.elapsed();

            let final_stats = memory_stats().unwrap_or(memory_stats::MemoryStats {
                physical_mem: 0,
                virtual_mem: 0,
            });
            let final_physical = final_stats.physical_mem as f64 / (1024.0 * 1024.0);
            let final_delta = final_physical - baseline_memory;

            let iter_peak_delta_mb = (iteration_peak - baseline_memory).max(final_delta);
            let iter_avg_delta_mb = if iteration_samples.is_empty() {
                final_delta.max(0.0)
            } else {
                iteration_samples.iter().sum::<f64>() / iteration_samples.len() as f64
            };

            if iter_peak_delta_mb > peak_memory_delta_mb {
                peak_memory_delta_mb = iter_peak_delta_mb;
            }
            avg_memory_samples.push(iter_avg_delta_mb);

            info!(
                "=== Iteration {} === Peak Delta: {:.2} MB, Avg Delta: {:.2} MB ({:?}, {} samples)",
                i + 1,
                iter_peak_delta_mb,
                iter_avg_delta_mb,
                operation_duration,
                sample_count
            );
        }

        let overall_avg_delta_mb = if avg_memory_samples.is_empty() {
            0.0
        } else {
            avg_memory_samples.iter().sum::<f64>() / avg_memory_samples.len() as f64
        };

        let memory_efficiency = if peak_memory_delta_mb > 0.0 {
            data_size as f64 / (peak_memory_delta_mb * 1024.0 * 1024.0)
        } else {
            0.0
        };

        info!(
            "Memory Summary - Peak Delta: {:.2} MB, Average Delta: {:.2} MB",
            peak_memory_delta_mb, overall_avg_delta_mb
        );

        let result = BenchmarkResult {
            test_name: "memory".to_string(),
            language: "rust".to_string(),
            data_size,
            concurrency: 1,
            encrypt_latency_ms: 0.0,
            decrypt_latency_ms: 0.0,
            end_to_end_latency_ms: 0.0,
            ops_per_second: 0.0,
            bytes_per_second: 0.0,
            peak_memory_mb: peak_memory_delta_mb,
            memory_efficiency_ratio: memory_efficiency,
            p50_latency: 0.0,
            p95_latency: 0.0,
            p99_latency: 0.0,
            timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            rust_version: env!("RUSTC_VERSION").to_string(),
            cpu_count: self.cpu_count,
            total_memory_gb: self.total_memory_gb,
            alloc: alloc.get_results(),
        };

        Ok(result)
    }

    /// Runs concurrent test with multiple workers to measure parallel performance
    async fn run_concurrent_test(
        &mut self,
        data_size: usize,
        concurrency: usize,
        iterations_per_worker: usize,
    ) -> Result<BenchmarkResult> {
        info!(
            "Running concurrent test - Size: {} bytes, Concurrency: {}",
            data_size, concurrency
        );

        let mut tasks = Vec::new();
        for worker_id in 0..concurrency {
            let esdk_client = self.esdk_client;
            let keyring = self.keyring.clone();

            let task = tokio::spawn(async move {
                let mut worker_times = Vec::new();
                for j in 0..iterations_per_worker {
                    // Per-worker data; heap to avoid stack overflow.
                    let worker_data = {
                        let mut data = vec![0u8; data_size];
                        rand::rng().fill(&mut data[..]);
                        data
                    };

                    let iter_start = Instant::now();
                    Self::encrypt_decrypt(&esdk_client, &keyring, &worker_data)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!("Worker {} iteration {} failed: {}", worker_id, j, e)
                        })?;
                    worker_times.push(iter_start.elapsed().as_secs_f64() * 1000.0);
                }
                Ok::<Vec<f64>, anyhow::Error>(worker_times)
            });
            tasks.push(task);
        }

        let start_time = Instant::now();
        let alloc = alloc::ResourceTracker::new();
        let results = join_all(tasks).await;
        let total_duration = start_time.elapsed().as_secs_f64();

        let mut all_times = Vec::new();
        for result in results {
            let worker_times = result??;
            all_times.extend(worker_times);
        }

        let total_ops = concurrency * iterations_per_worker;
        let total_bytes = total_ops * data_size;

        all_times.sort_by(|a, b| a.total_cmp(b));
        let result = BenchmarkResult {
            test_name: "concurrent".to_string(),
            language: "rust".to_string(),
            data_size,
            concurrency,
            encrypt_latency_ms: 0.0,
            decrypt_latency_ms: 0.0,
            end_to_end_latency_ms: average(&all_times),
            ops_per_second: total_ops as f64 / total_duration,
            bytes_per_second: total_bytes as f64 / total_duration,
            p50_latency: percentile(&all_times, 50.0),
            p95_latency: percentile(&all_times, 95.0),
            p99_latency: percentile(&all_times, 99.0),
            peak_memory_mb: 0.0,
            memory_efficiency_ratio: 0.0,
            timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            rust_version: env!("RUSTC_VERSION").to_string(),
            cpu_count: self.cpu_count,
            total_memory_gb: self.total_memory_gb,
            alloc: alloc.get_results(),
        };

        info!(
            "Concurrent test completed - Ops/sec: {:.2}, Avg latency: {:.2} ms",
            result.ops_per_second, result.end_to_end_latency_ms
        );

        Ok(result)
    }

    async fn run_throughput_tests(&mut self, data_sizes: &[usize], iterations: usize) {
        info!("Running throughput tests...");
        for &data_size in data_sizes {
            match self.run_throughput_test(data_size, iterations).await {
                Ok(result) => {
                    info!(
                        "Throughput test completed: {:.2} ops/sec",
                        result.ops_per_second
                    );
                    self.results.push(result);
                }
                Err(e) => {
                    warn!("Throughput test failed: {}", e);
                }
            }
        }
    }

    async fn run_memory_tests(&mut self, data_sizes: &[usize]) {
        info!("Running memory tests...");
        for &data_size in data_sizes {
            match self.run_memory_test(data_size).await {
                Ok(result) => {
                    info!(
                        "Memory test completed: {:.2} MB peak",
                        result.peak_memory_mb
                    );
                    self.results.push(result);
                }
                Err(e) => {
                    warn!("Memory test failed: {}", e);
                }
            }
        }
    }

    async fn run_concurrency_tests(&mut self, data_sizes: &[usize], concurrency_levels: &[usize]) {
        info!("Running concurrency tests...");
        for &data_size in data_sizes {
            for &concurrency in concurrency_levels {
                if concurrency > 1 {
                    match self.run_concurrent_test(data_size, concurrency, 5).await {
                        Ok(result) => {
                            info!(
                                "Concurrent test completed: {:.2} ops/sec @ {} threads",
                                result.ops_per_second, concurrency
                            );
                            self.results.push(result);
                        }
                        Err(e) => {
                            warn!("Concurrent test failed: {}", e);
                        }
                    }
                }
            }
        }
    }

    pub async fn run_all_benchmarks(&mut self, is_quick_mode: bool) -> Result<()> {
        info!(
            "Starting ESDK benchmark suite ({} keyring)",
            self.keyring_name
        );

        let mut data_sizes = Vec::new();
        data_sizes.extend(&self.config.data_sizes.small);
        data_sizes.extend(&self.config.data_sizes.medium);
        data_sizes.extend(&self.config.data_sizes.large);

        let concurrency_levels = self.config.concurrency_levels.clone();

        if self.should_run_test_type("throughput", is_quick_mode) {
            self.run_throughput_tests(&data_sizes, self.config.iterations.measurement)
                .await;
        } else {
            info!("Skipping throughput tests (not in test_types)");
        }

        if self.should_run_test_type("memory", is_quick_mode) {
            self.run_memory_tests(&data_sizes).await;
        } else {
            info!("Skipping memory tests (not in test_types)");
        }

        if self.should_run_test_type("concurrency", is_quick_mode) {
            self.run_concurrency_tests(&data_sizes, &concurrency_levels)
                .await;
        } else {
            info!("Skipping concurrency tests (not in test_types)");
        }

        info!(
            "Benchmark suite completed. Total results: {}",
            self.results.len()
        );
        Ok(())
    }
}
