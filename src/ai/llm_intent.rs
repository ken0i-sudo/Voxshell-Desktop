use crate::error::VoxError;
use crate::executors::dry_run::{CollisionPolicy, FileActionType, FileIntentRequest};
use crate::security::sandbox::BaseDirEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntentActionType {
    AppInstall,
    AppUninstall,
    AppUpgrade,
    AppSearch,
    AppList,
    FileMove,
    FileCopy,
    FileRename,
    FileDelete,
    DirCreate,
    SystemUndo,
    UnsupportedIntent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentParameters {
    pub package_query: Option<String>,
    pub source_base_dir: Option<BaseDirEnum>,
    pub source_relative_path: Option<String>,
    pub file_filter_extensions: Option<Vec<String>>,
    pub file_name_contains: Option<String>,
    pub destination_base_dir: Option<BaseDirEnum>,
    pub destination_relative_path: Option<String>,
    pub create_destination_if_missing: Option<bool>,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub upgrade_all: bool,
    pub collision_policy: Option<CollisionPolicy>,
}

/// Strict Rust representation of `VoxShellIntentPayload` (`SRS Section 3.1`).
/// `#[serde(deny_unknown_fields)]` guarantees any hallucinated LLM property is rejected immediately.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoxShellIntentPayload {
    pub action_type: IntentActionType,
    pub human_summary: String,
    pub parameters: IntentParameters,
}

impl VoxShellIntentPayload {
    /// Parses and validates a raw JSON string returned by the LLM.
    pub fn from_llm_json(raw_json: &str) -> Result<Self, VoxError> {
        serde_json::from_str::<VoxShellIntentPayload>(raw_json).map_err(|e| {
            VoxError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid LLM JSON intent schema: {}", e),
            ))
        })
    }

    /// Converts the validated LLM intent into a `FileIntentRequest` if it is a file/directory action.
    pub fn to_file_intent_request(
        &self,
        command_id: &str,
        raw_transcript: &str,
    ) -> Option<FileIntentRequest> {
        let file_action = match self.action_type {
            IntentActionType::FileMove => FileActionType::FileMove,
            IntentActionType::FileCopy => FileActionType::FileCopy,
            IntentActionType::FileRename => FileActionType::FileRename,
            IntentActionType::FileDelete => FileActionType::FileDelete,
            IntentActionType::DirCreate => FileActionType::DirCreate,
            _ => return None,
        };

        Some(FileIntentRequest {
            command_id: command_id.to_string(),
            raw_transcript: raw_transcript.to_string(),
            action_type: file_action,
            human_summary: self.human_summary.clone(),
            source_base_dir: self.parameters.source_base_dir,
            source_relative_path: self.parameters.source_relative_path.clone(),
            file_filter_extensions: self.parameters.file_filter_extensions.clone(),
            file_name_contains: self.parameters.file_name_contains.clone(),
            destination_base_dir: self.parameters.destination_base_dir,
            destination_relative_path: self.parameters.destination_relative_path.clone(),
            create_destination_if_missing: self
                .parameters
                .create_destination_if_missing
                .unwrap_or(true),
            recursive: self.parameters.recursive,
            collision_policy: self.parameters.collision_policy.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_llm_json_schema_deserialization_and_unknown_field_rejection() {
        let valid_json = r#"{
            "action_type": "FILE_MOVE",
            "human_summary": "Move all PDFs from Downloads to Documents/Invoices",
            "parameters": {
                "package_query": null,
                "source_base_dir": "DOWNLOADS",
                "source_relative_path": null,
                "file_filter_extensions": ["pdf"],
                "file_name_contains": null,
                "destination_base_dir": "DOCUMENTS",
                "destination_relative_path": "Invoices",
                "create_destination_if_missing": true,
                "recursive": false,
                "upgrade_all": false,
                "collision_policy": "AUTO_RENAME"
            }
        }"#;

        let parsed = VoxShellIntentPayload::from_llm_json(valid_json)
            .expect("Valid SRS 3.1 JSON should deserialize");
        assert_eq!(parsed.action_type, IntentActionType::FileMove);
        assert_eq!(
            parsed.parameters.source_base_dir,
            Some(BaseDirEnum::Downloads)
        );

        let file_req = parsed
            .to_file_intent_request("cmd_123", "Move all PDFs")
            .unwrap();
        assert_eq!(file_req.action_type, FileActionType::FileMove);

        // Verify that an injected `shell_command` field is rejected by `deny_unknown_fields`
        let malicious_json = r#"{
            "action_type": "FILE_MOVE",
            "human_summary": "Injected field test",
            "shell_command": "rm -rf /",
            "parameters": {}
        }"#;
        assert!(VoxShellIntentPayload::from_llm_json(malicious_json).is_err());
    }
}
