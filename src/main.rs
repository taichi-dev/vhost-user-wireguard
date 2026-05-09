// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser as _;
use vhost_user_wireguard::config::cli::CliArgs;

fn main() -> std::process::ExitCode {
    let cli = CliArgs::parse();
    match vhost_user_wireguard::run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fatal: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
