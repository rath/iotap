use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = iotap::cli::Cli::parse();
    match iotap::app::run(&cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("iotap: {err:#}");
            ExitCode::FAILURE
        }
    }
}
