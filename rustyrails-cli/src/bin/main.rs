use std::{path::PathBuf, process::exit};

use clap::{Parser, Subcommand};
use rand::{distributions::Alphanumeric, thread_rng, Rng};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new rustyrails website
    New {
        /// Local path to copy the template from.
        #[arg(name = "path", default_value = ".")]
        path: PathBuf,

        /// Folder name of folder template
        #[arg(short, long, default_value = "rustyrails-site")]
        folder_name: String,

        /// Rust lib name in Cargo.toml.
        #[arg(short, long)]
        lib_name: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let res = match cli.command {
        Commands::New {
            path,
            folder_name,
            lib_name,
        } => {
            let random_string: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(20)
                .map(char::from)
                .collect();

            let mut define = vec![format!("auth_secret={random_string}")];
            if let Some(lib_name) = lib_name {
                define.push(format!("lib_name={lib_name}"));
            }
            match rustyrails_cli::generate::demo_site(&path, &folder_name, Some(define)) {
                Ok(path) => rustyrails_cli::CmdExit {
                    code: 0,
                    message: Some(format!(
                        "\n💥 Rustyrails generated successfully in path: {}",
                        path.display()
                    )),
                },
                Err(err) => rustyrails_cli::CmdExit {
                    code: 0,
                    message: Some(format!("{err}")),
                },
            }
        }
    };

    if let Some(message) = res.message {
        eprintln!("{message}");
    };

    exit(res.code);
}
