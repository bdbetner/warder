use std::path::{Path, PathBuf};
use std::time::SystemTime;

use warder_config::EnvironmentSupport;

use crate::{
    launch_supervised_run, render_all_journals_from_db, render_dry_run_from_config,
    render_pre_launch_readiness_for_run, render_session_receipt_from_db, CliCommand, CliError,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DemoKind {
    AttackPack,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttackPackDemoOptions {
    pub root: PathBuf,
    pub network_url: String,
}

pub fn default_attack_pack_root() -> PathBuf {
    std::env::temp_dir().join(format!("warder-attack-pack-{}", std::process::id()))
}

pub fn run_attack_pack_demo(
    options: &AttackPackDemoOptions,
    environment: &EnvironmentSupport,
) -> Result<String, CliError> {
    if options.root.try_exists().map_err(|error| CliError {
        message: format!(
            "failed to inspect demo root '{}': {error}",
            options.root.display()
        ),
    })? {
        return Err(CliError {
            message: format!(
                "demo root '{}' already exists; choose a fresh --root path",
                options.root.display()
            ),
        });
    }

    let db_path = options.root.join("warder.sqlite3");
    let config_path = options.root.join("attack-pack.toml");
    let workspace_root = options.root.join("workspace");
    let protected_root = options.root.join("protected-secret");
    let protected_file = protected_root.join("secret.txt");
    let workspace_file = workspace_root.join("allowed.txt");
    let status_file = workspace_root.join("probe-status.txt");

    std::fs::create_dir_all(&workspace_root).map_err(|error| CliError {
        message: format!(
            "failed to create demo workspace '{}': {error}",
            workspace_root.display()
        ),
    })?;
    std::fs::create_dir_all(&protected_root).map_err(|error| CliError {
        message: format!(
            "failed to create demo protected path '{}': {error}",
            protected_root.display()
        ),
    })?;
    std::fs::write(&protected_file, "do-not-change\n").map_err(|error| CliError {
        message: format!(
            "failed to write demo secret '{}': {error}",
            protected_file.display()
        ),
    })?;
    std::fs::write(
        &config_path,
        render_attack_pack_config(&workspace_root, &protected_root),
    )
    .map_err(|error| CliError {
        message: format!(
            "failed to write demo config '{}': {error}",
            config_path.display()
        ),
    })?;

    let dry_run_command = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let run_command = CliCommand::Run {
        config: Some(config_path.clone()),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,
        agent: "attack-pack-shell".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            attack_pack_script(
                &protected_file,
                &workspace_file,
                &status_file,
                &options.network_url,
            ),
        ],
    };

    let mut lines = vec![
        "Warder attack-pack demo".to_string(),
        format!("workspace: {}", workspace_root.display()),
        format!("protected: {}", protected_root.display()),
        "This demo attempts a protected write, a protected read, a workspace edit, and a network connection.".to_string(),
        "Warder reports what this host blocked, observed, or degraded.".to_string(),
        String::new(),
        "== dry run ==".to_string(),
        render_dry_run_from_config(
            Some(config_path.clone()),
            "attack-pack-shell",
            &dry_run_command,
            environment,
        )?,
        String::new(),
        "== launch readiness ==".to_string(),
        render_pre_launch_readiness_for_run(&run_command, environment)?,
        String::new(),
        "== launch ==".to_string(),
    ];
    let outcome = launch_supervised_run(&run_command, environment, SystemTime::now())?;
    lines.push(format!("session {} launched", outcome.session_id));
    for warning in outcome.validation_warnings {
        lines.push(format!("warning: {warning}"));
    }
    match outcome.exit_code {
        Some(code) => lines.push(format!("agent command exited with code {code}")),
        None => lines.push("agent command exited without a status code".to_string()),
    }
    if let Ok(status) = std::fs::read_to_string(&status_file) {
        lines.push(format!("agent probe result: {}", status.trim()));
    }

    lines.push(String::new());
    lines.push("== receipt ==".to_string());
    lines.push(render_session_receipt_from_db(
        Some(db_path.clone()),
        &outcome.session_id,
    )?);

    lines.push(String::new());
    if std::fs::read_to_string(&protected_file)
        .unwrap_or_default()
        .contains("changed")
    {
        lines.push("result: protected write was not blocked on this host/config.".to_string());
        lines.push(
            "review the degraded protection section above before trusting enforcement.".to_string(),
        );
    } else {
        lines.push("result: protected write did not modify the secret file.".to_string());
    }
    if workspace_file.try_exists().map_err(|error| CliError {
        message: format!(
            "failed to inspect demo workspace result '{}': {error}",
            workspace_file.display()
        ),
    })? {
        lines.push("result: workspace edit was allowed.".to_string());
    } else {
        return Err(CliError {
            message: "expected workspace edit to be allowed".to_string(),
        });
    }

    lines.push(String::new());
    lines.push("== journals ==".to_string());
    lines.push(render_all_journals_from_db(
        Some(db_path),
        Some(&outcome.session_id),
    )?);

    Ok(lines.join("\n"))
}

pub fn render_attack_pack_config(workspace_root: &Path, protected_root: &Path) -> String {
    format!(
        "[enforcement]\n\
landlock = \"best-effort\"\n\
cgroups = \"best-effort\"\n\
writable-roots = [{workspace_root}]\n\n\
[network]\n\
journal = true\n\n\
[[zones]]\n\
id = \"demo-secret\"\n\
name = \"Demo Secret\"\n\
description = \"Throwaway secret path for Warder's attack-pack demo.\"\n\
paths = [{protected_root}]\n\
write_policy = \"deny\"\n\
# Read protection is intentionally off for the default demo. Warder should say\n\
# that clearly in the receipt; enable read-deny in a separate strict host test.\n\
read-deny = false\n\
snapshot = \"disabled\"\n\n\
[[agents]]\n\
id = \"attack-pack-shell\"\n\
label = \"Attack Pack Shell\"\n\
command = \"sh\"\n\
profile = \"local-script\"\n",
        workspace_root = toml_string(&workspace_root.display().to_string()),
        protected_root = toml_string(&protected_root.display().to_string()),
    )
}

fn attack_pack_script(
    protected_file: &Path,
    workspace_file: &Path,
    status_file: &Path,
    network_url: &str,
) -> String {
    format!(
        "set +e\n\
printf changed > {protected_file}\n\
protected_write_status=$?\n\
cat {protected_file} >/dev/null\n\
protected_read_status=$?\n\
printf allowed > {workspace_file}\n\
workspace_write_status=$?\n\
if command -v curl >/dev/null 2>&1; then\n\
  curl -fsS --max-time 2 {network_url} >/dev/null 2>&1\n\
  network_status=$?\n\
else\n\
  network_status=127\n\
fi\n\
printf 'protected_write=%s protected_read=%s workspace_write=%s network=%s\\n' \"$protected_write_status\" \"$protected_read_status\" \"$workspace_write_status\" \"$network_status\" > {status_file}\n\
exit 0",
        protected_file = shell_quote(&protected_file.display().to_string()),
        workspace_file = shell_quote(&workspace_file.display().to_string()),
        status_file = shell_quote(&status_file.display().to_string()),
        network_url = shell_quote(network_url),
    )
}

fn toml_string(value: &str) -> String {
    let mut quoted = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

fn shell_quote(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}
