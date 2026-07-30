// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod alloc;
mod benchmark;
mod config;
mod results;
mod tests;

use anyhow::Result;
use clap::{Arg, ArgAction, Command};

use benchmark::EsdkBenchmark;

fn main() -> Result<()> {
    // Default worker stacks overflow decrypting 50 MiB payloads.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()?;

    rt.block_on(async { run_benchmark().await })
}

async fn run_benchmark() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let matches = Command::new("ESDK Rust Hierarchical Keyring Benchmark")
        .version(env!("CARGO_PKG_VERSION"))
        .about("AWS Encryption SDK performance benchmark — Rust, hierarchical keyring")
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("FILE")
                .help("Path to test configuration file")
                .default_value("config/test-scenarios.yaml"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .value_name("FILE")
                .help("Path to output results file")
                .default_value("results/raw-data/rust_results.json"),
        )
        .arg(
            Arg::new("quick")
                .long("quick")
                .help("Run quick test with reduced iterations")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let config_path = matches.get_one::<String>("config").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let quick = matches.get_flag("quick");

    let mut bench = EsdkBenchmark::new(config_path).await?;

    if quick {
        let quick_config = bench.config.quick_config.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Quick mode requested but no quick_config found in config file")
        })?;

        bench.config.iterations.measurement = quick_config.iterations.measurement;
        bench.config.iterations.warmup = quick_config.iterations.warmup;
        bench.config.data_sizes.small = quick_config.data_sizes.small.clone();
        bench.config.data_sizes.medium = Vec::new();
        bench.config.data_sizes.large = Vec::new();
        bench.config.concurrency_levels = quick_config.concurrency_levels.clone();
    }

    bench.run_all_benchmarks(quick).await?;

    // Exit non-zero when every scenario failed; the CloudWatch upload step
    // cannot consume an empty result set.
    if bench.results.is_empty() {
        anyhow::bail!("benchmark produced no results; all scenarios failed");
    }

    bench.save_results(output_path)?;

    println!("\n=== ESDK Rust Hierarchical Keyring Benchmark Summary ===");
    println!("Total tests completed: {}", bench.results.len());
    println!("Results saved to: {}", output_path);

    let max_throughput = bench
        .results
        .iter()
        .filter(|r| r.test_name == "throughput")
        .map(|r| r.ops_per_second)
        .fold(0.0, f64::max);
    if max_throughput > 0.0 {
        println!("Maximum throughput: {:.2} ops/sec", max_throughput);
    }

    Ok(())
}
