use serde::Deserialize;

pub fn extract_message_id(payload: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct IdOnly {
        id: Option<String>,
    }

    let parsed: IdOnly = serde_json::from_slice(payload).ok()?;
    parsed.id
}
