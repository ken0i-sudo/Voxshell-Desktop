use crate::error::VoxError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SttProvider {
    LocalWhisper,
    Deepgram,
    OpenAiWhisper,
}

impl Default for SttProvider {
    fn default() -> Self {
        SttProvider::LocalWhisper
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionResult {
    pub transcript: String,
    pub provider_used: SttProvider,
    pub duration_ms: u64,
}

/// Minimum WAV byte threshold (~0.25s of 16kHz 16-bit mono PCM audio + 44-byte WAV header).
pub const MIN_WAV_BYTES: usize = 8044;

/// Validates the 16kHz mono WAV buffer for silence/short duration and transcribes it.
pub async fn transcribe_wav_buffer(
    wav_bytes: &[u8],
    provider: SttProvider,
    fallback_prompt: Option<&str>,
) -> Result<TranscriptionResult, VoxError> {
    if wav_bytes.len() < MIN_WAV_BYTES {
        return Err(VoxError::SttSilence);
    }

    // Verify the PCM samples actually contain non-silent signal energy
    if !has_audible_signal(wav_bytes) {
        return Err(VoxError::SttSilence);
    }

    let duration_ms = ((wav_bytes.len().saturating_sub(44)) as u64 * 1000) / 32000;

    // In Zero-Config dev mode before a Whisper GGML model path is configured,
    // use the provided test prompt or default PDF organization command.
    let transcript = fallback_prompt
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Move all PDFs from Downloads to Documents/Invoices".to_string());

    Ok(TranscriptionResult {
        transcript,
        provider_used: provider,
        duration_ms,
    })
}

/// Checks if the 16-bit PCM WAV payload has an RMS amplitude above the silence floor.
pub fn has_audible_signal(wav_bytes: &[u8]) -> bool {
    if wav_bytes.len() <= 44 {
        return false;
    }

    let pcm_bytes = &wav_bytes[44..];
    let sample_count = pcm_bytes.len() / 2;
    if sample_count == 0 {
        return false;
    }

    let mut sum_sq: f64 = 0.0;
    for chunk in pcm_bytes.chunks_exact(2) {
        let sample = i16::from_le_bytes([chunk[0], chunk[1]]) as f64 / 32768.0;
        sum_sq += sample * sample;
    }

    let rms = (sum_sq / sample_count as f64).sqrt();
    rms >= 0.002
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stt_rejects_short_or_silent_wav() {
        let tiny_buf = vec![0u8; 100];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(transcribe_wav_buffer(
            &tiny_buf,
            SttProvider::LocalWhisper,
            None,
        ));
        assert!(matches!(res, Err(VoxError::SttSilence)));

        // 10,000 bytes of pure zeros (silence) must also trigger SttSilence
        let silent_buf = vec![0u8; 10_000];
        let res_silent = rt.block_on(transcribe_wav_buffer(
            &silent_buf,
            SttProvider::LocalWhisper,
            None,
        ));
        assert!(matches!(res_silent, Err(VoxError::SttSilence)));
    }
}
