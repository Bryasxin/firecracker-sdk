//! Firecracker types - custom wrappers for Firecracker Models
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceState {
    #[serde(rename = "Not Started", alias = "Not started")]
    NotStarted,
    #[serde(rename = "Running")]
    Running,
    #[serde(rename = "Paused")]
    Paused,
    #[serde(rename = "Stopped")]
    Stopped,
}

impl Default for InstanceState {
    fn default() -> Self {
        Self::NotStarted
    }
}

impl std::fmt::Display for InstanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstanceState::NotStarted => write!(f, "Not Started"),
            InstanceState::Running => write!(f, "Running"),
            InstanceState::Paused => write!(f, "Paused"),
            InstanceState::Stopped => write!(f, "Stopped"),
        }
    }
}

impl From<openapi::models::instance_info::State> for InstanceState {
    fn from(state: openapi::models::instance_info::State) -> Self {
        match state {
            openapi::models::instance_info::State::NotStarted => InstanceState::NotStarted,
            openapi::models::instance_info::State::Running => InstanceState::Running,
            openapi::models::instance_info::State::Paused => InstanceState::Paused,
        }
    }
}
