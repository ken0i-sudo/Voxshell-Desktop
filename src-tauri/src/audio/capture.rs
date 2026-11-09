use crate::error::VoxError;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, oneshot};

#[derive(Clone, Copy, Debug, Serialize)]
pub struct AudioLevelEvent {
    pub rms: f32,
}

/// Thread-safe (`Send + Sync`) handle to an active microphone capture session.
pub struct AudioCaptureHandle {
    stop_tx: Option<oneshot::Sender<()>>,
    audio_buffer: Arc<Mutex<Vec<f32>>>,
    sample_rate: u32,
    channels: u16,
    level_rx: broadcast::Receiver<AudioLevelEvent>,
}

impl AudioCaptureHandle {
    /// Stops the microphone stream and encodes the captured samples into a 16kHz mono WAV buffer.
    pub fn stop_and_get_wav(&mut self) -> Result<Vec<u8>, VoxError> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        let samples = self
            .audio_buffer
            .lock()
            .map_err(|_| VoxError::Io(std::io::Error::new(std::io::ErrorKind::Other, "Audio mutex poisoned")))?
            .clone();

        encode_f32_pcm_to_wav_bytes(&samples, self.sample_rate, self.channels)
    }

    pub fn subscribe_levels(&self) -> broadcast::Receiver<AudioLevelEvent> {
        self.level_rx.resubscribe()
    }
}

pub fn start_audio_capture() -> Result<AudioCaptureHandle, VoxError> {
    let host = cpal::default_host();
    let device = host.default_input_device().ok_or_else(|| {
        VoxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No microphone input device found",
        ))
    })?;

    let default_cfg = device.default_input_config().map_err(|e| {
        VoxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    })?;

    let sample_rate = default_cfg.sample_rate().0;
    let channels = default_cfg.channels();
    let config: cpal::StreamConfig = default_cfg.into();

    let audio_buffer = Arc::new(Mutex::new(Vec::<f32>::new()));
    let buf_clone = Arc::clone(&audio_buffer);
    let (level_tx, level_rx) = broadcast::channel(64);
    let (stop_tx, stop_rx) = oneshot::channel::<()>();

    // Spawn dedicated OS thread because `cpal::Stream` is `!Send` on ALSA/WASAPI
    std::thread::spawn(move || {
        let stream_res = device.build_input_stream(
            &config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                let mut sum_sq = 0.0f32;
                if let Ok(mut locked) = buf_clone.lock() {
                    for &sample in data {
                        locked.push(sample);
                        sum_sq += sample * sample;
                    }
                }
                let rms = if !data.is_empty() {
                    (sum_sq / data.len() as f32).sqrt()
                } else {
                    0.0
                };
                let _ = level_tx.send(AudioLevelEvent { rms });
            },
            move |err| {
                eprintln!("[VoxShell Audio] Stream error: {}", err);
            },
            None,
        );

        if let Ok(stream) = stream_res {
            let _ = stream.play();
            // Keep stream alive until stop_rx receives signal or is dropped
            let _ = stop_rx.blocking_recv();
        }
    });

    Ok(AudioCaptureHandle {
        stop_tx: Some(stop_tx),
        audio_buffer,
        sample_rate,
        channels,
        level_rx,
    })
}

pub fn encode_f32_pcm_to_wav_bytes(
    samples: &[f32],
    sample_rate: u32,
    channels: u16,
) -> Result<Vec<u8>, VoxError> {
    let spec = hound::WavSpec {
        channels,
        sample_rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = hound::WavWriter::new(&mut cursor, spec).map_err(|e| {
            VoxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })?;

        for &sample in samples {
            let clamped = sample.clamp(-1.0, 1.0);
            let scaled = (clamped * 32767.0) as i16;
            writer.write_sample(scaled).map_err(|e| {
                VoxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            })?;
        }
        writer.finalize().map_err(|e| {
            VoxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })?;
    }

    Ok(cursor.into_inner())
}
