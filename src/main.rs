mod config;
mod decode;
mod frontend;
mod reference;
mod server;

use std::ffi::{OsStr, OsString};
use std::sync::Arc;

use config::create_config;
use reference::parse_extra_trusted;
use server::AppState;

fn main() {
    install_process_panic_handler();

    match startup_action(std::env::args_os().skip(1)) {
        StartupAction::Run => {}
        StartupAction::PrintVersion => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            return;
        }
        StartupAction::Error(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    }

    let config = create_config();
    let extra_trusted = parse_extra_trusted(config.trusted_provider_signers.as_deref())
        .unwrap_or_else(|error| panic!("invalid TRUSTED_PROVIDER_SIGNERS: {error}"));

    println!(
        "{}",
        serde_json::json!({
            "message": "starting atlas transaction decoder",
            "defaultChainId": config.default_chain_id,
            "maxInputBytes": config.max_input_bytes.get(),
            "extraTrustedSigners": extra_trusted.len(),
        })
    );

    let worker_threads = config.web_workers.get();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_io()
        .enable_time()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async move {
        let app_state = AppState {
            html_title: Arc::new(config.html_title.clone()),
            max_input_bytes: config.max_input_bytes.get(),
            default_chain_id: config.default_chain_id,
            extra_trusted: Arc::new(extra_trusted),
        };

        server::run_server(
            app_state,
            config.listen_host.clone(),
            config.listen_port.get(),
        )
        .await;
    });
}

fn install_process_panic_handler() {
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("uncaught panic: {panic_info}");
    }));
}

#[derive(Debug, PartialEq, Eq)]
enum StartupAction {
    Run,
    PrintVersion,
    Error(String),
}

fn startup_action<I>(args: I) -> StartupAction
where
    I: IntoIterator<Item = OsString>,
{
    let mut saw_version = false;

    for arg in args {
        if arg == OsStr::new("-v") || arg == OsStr::new("--version") {
            saw_version = true;
            continue;
        }

        return StartupAction::Error(format!(
            "unsupported command-line argument: {}. Use environment variables to configure atlas-transaction-decoder; command-line arguments are not supported.",
            arg.to_string_lossy()
        ));
    }

    if saw_version {
        StartupAction::PrintVersion
    } else {
        StartupAction::Run
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn no_arguments_runs_service() {
        assert_eq!(startup_action(args(&[])), StartupAction::Run);
    }

    #[test]
    fn version_arguments_print_version() {
        assert_eq!(startup_action(args(&["-v"])), StartupAction::PrintVersion);
        assert_eq!(
            startup_action(args(&["--version"])),
            StartupAction::PrintVersion
        );
    }

    #[test]
    fn invalid_argument_returns_error() {
        match startup_action(args(&["--port", "8080"])) {
            StartupAction::Error(message) => {
                assert!(message.contains("--port"));
                assert!(message.contains("environment variables"));
            }
            action => panic!("expected error action, got {action:?}"),
        }
    }
}
