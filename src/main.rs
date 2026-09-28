use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = iotap::cli::Cli::parse();
    match iotap::app::run(&cli) {
        Ok(code) => code,
        Err(err) => {
            // Not `eprintln!`, which panics when stderr cannot be written to, as after the
            // terminal it belongs to has hung up.
            let _ = writeln!(io::stderr(), "iotap: {err:#}");
            ExitCode::FAILURE
        }
    }
}
