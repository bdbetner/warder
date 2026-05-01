use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiConfigDraft {
    pub agent: GuiAgentConfig,
    pub protected_paths: Vec<GuiProtectedPath>,
    pub network_journal: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiAgentConfig {
    pub id: String,
    pub label: String,
    pub command: String,
    pub profile: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiProtectedPath {
    pub id: String,
    pub label: String,
    pub path: String,
    pub read_protected: bool,
    pub write_protected: bool,
    pub snapshot: bool,
}

pub fn render_gui_config_toml(draft: &GuiConfigDraft) -> Result<String, String> {
    validate_draft(draft)?;

    let mut root = toml::map::Map::new();
    root.insert("enforcement".to_string(), enforcement_table());
    root.insert("network".to_string(), network_table(draft.network_journal));
    root.insert("agents".to_string(), agents_array(draft));
    root.insert("zones".to_string(), zones_array(draft));

    toml::to_string_pretty(&toml::Value::Table(root))
        .map_err(|error| format!("failed to render config TOML: {error}"))
}

fn validate_draft(draft: &GuiConfigDraft) -> Result<(), String> {
    if draft.agent.id.trim().is_empty() {
        return Err("agent id is required".to_string());
    }
    if draft.agent.command.trim().is_empty() {
        return Err("agent command is required".to_string());
    }
    if draft.protected_paths.is_empty() {
        return Err("at least one protected path is required".to_string());
    }
    for path in &draft.protected_paths {
        if path.id.trim().is_empty() {
            return Err("protected path id is required".to_string());
        }
        if path.path.trim().is_empty() {
            return Err(format!("protected path '{}' must include a path", path.id));
        }
        if !path.read_protected && !path.write_protected {
            return Err(format!(
                "protected path '{}' must enable read or write protection",
                path.id
            ));
        }
    }
    Ok(())
}

fn enforcement_table() -> toml::Value {
    let mut table = toml::map::Map::new();
    table.insert(
        "landlock".to_string(),
        toml::Value::String("best-effort".to_string()),
    );
    table.insert(
        "cgroups".to_string(),
        toml::Value::String("best-effort".to_string()),
    );
    toml::Value::Table(table)
}

fn network_table(enabled: bool) -> toml::Value {
    let mut table = toml::map::Map::new();
    table.insert("journal".to_string(), toml::Value::Boolean(enabled));
    toml::Value::Table(table)
}

fn agents_array(draft: &GuiConfigDraft) -> toml::Value {
    let mut agent = toml::map::Map::new();
    agent.insert(
        "id".to_string(),
        toml::Value::String(draft.agent.id.clone()),
    );
    agent.insert(
        "label".to_string(),
        toml::Value::String(draft.agent.label.clone()),
    );
    agent.insert(
        "command".to_string(),
        toml::Value::String(draft.agent.command.clone()),
    );
    if let Some(profile) = &draft.agent.profile {
        agent.insert("profile".to_string(), toml::Value::String(profile.clone()));
    }
    toml::Value::Array(vec![toml::Value::Table(agent)])
}

fn zones_array(draft: &GuiConfigDraft) -> toml::Value {
    toml::Value::Array(
        draft
            .protected_paths
            .iter()
            .map(|path| {
                let mut zone = toml::map::Map::new();
                zone.insert("id".to_string(), toml::Value::String(path.id.clone()));
                zone.insert("name".to_string(), toml::Value::String(path.label.clone()));
                zone.insert(
                    "description".to_string(),
                    toml::Value::String(description_for(path)),
                );
                zone.insert(
                    "paths".to_string(),
                    toml::Value::Array(vec![toml::Value::String(path.path.clone())]),
                );
                zone.insert(
                    "write-policy".to_string(),
                    toml::Value::String(
                        if path.write_protected {
                            "deny"
                        } else {
                            "allow"
                        }
                        .to_string(),
                    ),
                );
                zone.insert(
                    "snapshot".to_string(),
                    toml::Value::String(
                        if path.snapshot {
                            "best-effort"
                        } else {
                            "disabled"
                        }
                        .to_string(),
                    ),
                );
                toml::Value::Table(zone)
            })
            .collect(),
    )
}

fn description_for(path: &GuiProtectedPath) -> String {
    match (path.read_protected, path.write_protected) {
        (true, true) => {
            "GUI-managed path with read visibility noted and write protection requested."
                .to_string()
        }
        (true, false) => "GUI-managed path with read visibility noted.".to_string(),
        (false, true) => "GUI-managed path with write protection requested.".to_string(),
        (false, false) => "GUI-managed path with no protection requested.".to_string(),
    }
}
