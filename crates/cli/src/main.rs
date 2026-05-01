fn main() {
    if warder_cli::is_internal_daemon_run_command(std::env::args()) {
        match warder_cli::parse_internal_daemon_run_options(std::env::args()) {
            Ok(options) => warder_cli::run_internal_daemon_forever(options),
            Err(error) => exit_with_error(error),
        }
    }

    match warder_cli::parse_args(std::env::args()) {
        Ok(warder_cli::CliCommand::Help) => {
            println!("{}", warder_cli::usage());
        }
        Ok(warder_cli::CliCommand::Version) => {
            println!("{}", warder_cli::version());
        }
        Ok(warder_cli::CliCommand::Start { config }) => {
            match warder_cli::start_daemon_runtime_with_config(None, config) {
                Ok(status) => println!("{status}"),
                Err(error) => exit_with_error(error),
            }
        }
        Ok(warder_cli::CliCommand::Stop) => match warder_cli::stop_daemon_runtime(None) {
            Ok(status) => println!("{status}"),
            Err(error) => exit_with_error(error),
        },
        Ok(warder_cli::CliCommand::Status) => {
            match warder_cli::render_daemon_status_from_runtime(None) {
                Ok(status) => println!("{status}"),
                Err(error) => eprintln!(
                    "warning: failed to read daemon runtime state: {}",
                    error.message
                ),
            }
            let report = warder_daemon::DaemonCapabilityReport::from_probe(
                warder_daemon::probe_current_host(),
            );
            println!("{}", warder_daemon::render_status(&report));
        }
        Ok(warder_cli::CliCommand::Doctor { config }) => {
            match warder_cli::render_host_doctor_from_probe_with_config(
                warder_daemon::probe_current_host(),
                config,
            ) {
                Ok(report) => println!("{report}"),
                Err(error) => exit_with_error(error),
            }
        }
        Ok(warder_cli::CliCommand::Init {
            output,
            profile,
            protected_paths,
            agent_command,
            force,
            print,
        }) => {
            let result = if print {
                warder_cli::render_starter_config(
                    &profile,
                    &protected_paths,
                    agent_command.as_deref(),
                )
            } else {
                warder_cli::write_starter_config(
                    output,
                    &profile,
                    &protected_paths,
                    agent_command.as_deref(),
                    force,
                )
            };
            match result {
                Ok(status) => println!("{status}"),
                Err(error) => exit_with_error(error),
            }
        }
        Ok(warder_cli::CliCommand::Profiles { format }) => match format {
            warder_cli::ProfileCatalogFormat::Text => {
                println!("{}", warder_cli::render_agent_profile_catalog());
            }
            warder_cli::ProfileCatalogFormat::Json => {
                match warder_cli::render_agent_profile_catalog_json() {
                    Ok(catalog) => println!("{catalog}"),
                    Err(error) => exit_with_error(error),
                }
            }
        },
        Ok(warder_cli::CliCommand::Explain { config }) => {
            match warder_cli::render_policy_explain_from_config(
                Some(config),
                &current_environment_support(),
            ) {
                Ok(explanation) => println!("{explanation}"),
                Err(error) => exit_with_error(error),
            }
        }
        Ok(warder_cli::CliCommand::DryRun {
            config,
            agent,
            command,
        }) => {
            match warder_cli::render_dry_run_from_config(
                Some(config),
                &agent,
                &command,
                &current_environment_support(),
            ) {
                Ok(dry_run) => println!("{dry_run}"),
                Err(error) => exit_with_error(error),
            }
        }
        Ok(command @ warder_cli::CliCommand::Run { .. }) => {
            let environment = current_environment_support();
            match &command {
                warder_cli::CliCommand::Run { launch: true, .. } => {
                    println!("{}", warder_cli::render_pre_launch_readiness(&environment));
                    match warder_cli::launch_supervised_run(
                        &command,
                        &environment,
                        std::time::SystemTime::now(),
                    ) {
                        Ok(outcome) => {
                            println!("session {} launched", outcome.session_id);
                            for warning in outcome.validation_warnings {
                                println!("warning: {warning}");
                            }
                            match outcome.exit_code {
                                Some(code) => println!("agent command exited with code {code}"),
                                None => println!("agent command exited without a status code"),
                            }
                            print_session_receipt(&command, &outcome.session_id);
                        }
                        Err(error) => exit_with_error(error),
                    }
                }
                warder_cli::CliCommand::Run {
                    cgroup_root: Some(cgroup_root),
                    ..
                } => {
                    match warder_cli::prepare_supervised_run(
                        &command,
                        &environment,
                        std::time::SystemTime::now(),
                        cgroup_root.clone(),
                        std::process::id(),
                    ) {
                        Ok(outcome) => {
                            println!("session {} recorded", outcome.session_id);
                            for warning in outcome.validation_warnings {
                                println!("warning: {warning}");
                            }
                            println!(
                                "cgroup tagging was attempted for the current launcher process"
                            );
                            println!("agent command was not launched");
                            print_session_receipt(&command, &outcome.session_id);
                        }
                        Err(error) => exit_with_error(error),
                    }
                }
                _ => {
                    match warder_cli::create_run_session(
                        &command,
                        &environment,
                        std::time::SystemTime::now(),
                    ) {
                        Ok(outcome) => {
                            println!("session {} recorded", outcome.session_id);
                            for warning in outcome.validation_warnings {
                                println!("warning: {warning}");
                            }
                            println!("agent command was not launched");
                            print_session_receipt(&command, &outcome.session_id);
                        }
                        Err(error) => exit_with_error(error),
                    }
                }
            }
        }
        Ok(warder_cli::CliCommand::Journal {
            db,
            session_id,
            kind,
        }) => {
            let journal = match kind {
                warder_cli::JournalKind::File => {
                    warder_cli::render_file_journal_from_db(db, session_id.as_deref())
                }
                warder_cli::JournalKind::Network => {
                    warder_cli::render_network_journal_from_db(db, session_id.as_deref())
                }
                warder_cli::JournalKind::All => {
                    warder_cli::render_all_journals_from_db(db, session_id.as_deref())
                }
            };
            match journal {
                Ok(journal) => println!("{journal}"),
                Err(error) => exit_with_error(error),
            }
        }
        Ok(warder_cli::CliCommand::Receipt {
            db,
            session_id,
            format,
            signing_key_file,
            verify_signature,
        }) => {
            match warder_cli::render_session_receipt_from_db_with_options(
                db,
                &session_id,
                format,
                signing_key_file.as_deref(),
                verify_signature.as_deref(),
            ) {
                Ok(receipt) => println!("{receipt}"),
                Err(error) => exit_with_error(error),
            }
        }
        Ok(warder_cli::CliCommand::Snapshot {
            session_id,
            config: Some(config),
            snapshot_root: Some(snapshot_root),
        }) => match warder_cli::create_snapshot_from_config(config, snapshot_root, &session_id) {
            Ok(report) => println!("{report}"),
            Err(error) => exit_with_error(error),
        },
        Ok(warder_cli::CliCommand::Revert {
            snapshot_id,
            snapshot_root: Some(snapshot_root),
            db,
            session_id,
            preview,
        }) => {
            let result = if preview {
                warder_cli::render_revert_preview(snapshot_root, &snapshot_id)
            } else if let (Some(db), Some(session_id)) = (db, session_id) {
                warder_cli::restore_snapshot_from_root_for_session(
                    db,
                    &session_id,
                    snapshot_root,
                    &snapshot_id,
                )
            } else {
                warder_cli::restore_snapshot_from_root(snapshot_root, &snapshot_id)
            };
            match result {
                Ok(report) => println!("{report}"),
                Err(error) => exit_with_error(error),
            }
        }
        Ok(command) => {
            if let Some(error) = warder_cli::command_not_implemented_error(&command) {
                exit_with_error(error);
            }
            println!("{}", warder_cli::command_summary(&command));
        }
        Err(error) => {
            eprintln!("error: {}", error.message);
            eprintln!("{}", warder_cli::usage());
            std::process::exit(2);
        }
    }
}

fn exit_with_error(error: warder_cli::CliError) -> ! {
    eprintln!("error: {}", error.message);
    std::process::exit(2);
}

fn print_session_receipt(command: &warder_cli::CliCommand, session_id: &str) {
    let warder_cli::CliCommand::Run { db, .. } = command else {
        return;
    };
    match warder_cli::render_session_receipt_from_db(db.clone(), session_id) {
        Ok(receipt) => println!("{receipt}"),
        Err(error) => eprintln!(
            "warning: failed to render session receipt: {}",
            error.message
        ),
    }
}

fn current_environment_support() -> warder_config::EnvironmentSupport {
    warder_cli::environment_support_from_probe(warder_daemon::probe_current_host())
}
