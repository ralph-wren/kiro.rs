use super::base::EventPayload;
use crate::kiro::parser::{error::ParseResult, frame::Frame};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeteringEvent {
    pub unit: Option<String>,
    pub usage: Option<f64>,
}

impl MeteringEvent {
    pub fn credit_usage(&self) -> Option<f64> {
        (self.unit.as_deref() == Some("credit"))
            .then_some(self.usage)
            .flatten()
            .filter(|usage| usage.is_finite() && *usage >= 0.0)
    }
}
impl EventPayload for MeteringEvent {
    fn from_frame(frame: &Frame) -> ParseResult<Self> {
        frame.payload_as_json()
    }
}
