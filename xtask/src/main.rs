//! Maintenance tasks of the workspace, run with `cargo xtask <task>` (`cargo xtask help` lists them).

use anyhow::Result;
use clap::{Parser, Subcommand};

mod libc_checks;

#[derive(Parser)]
#[command(
    bin_name = "cargo xtask",
    about = "Maintenance tasks of the esp-idf workspace"
)]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Regenerate the `libc` items which `esp-idf-sys` checks, in `esp-idf-sys/build/libc_items.rs`
    ///
    /// Lists the public structs (with their public fields), the other types, the integer
    /// constants and the functions (with their symbols) which every given `libc` version has, for
    /// every given target and set of cfgs.
    /// The `esp-idf-sys` build script checks those of them which the ESP-IDF bindings have too.
    LibcChecks(libc_checks::LibcChecks),
}

fn main() -> Result<()> {
    match Cli::parse().task {
        Task::LibcChecks(args) => libc_checks::run(args),
    }
}
