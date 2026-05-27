use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::Ordering;

use ::pcap::{self, Active, Capture, Device as PcapDevice, Linktype};
use futures::executor::block_on;
use futures::{SinkExt, StreamExt, TryStreamExt};
use pcap::PacketCodec;
use tracing::{debug, instrument, warn};

use super::*;

pub struct PcapBackend;

impl PcapBackend {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone)]
pub struct PcapDeviceFilter {
    names: Vec<String>,
}

impl PcapDeviceFilter {
    pub fn new(names: Vec<String>) -> Self {
        Self { names }
    }

    fn matches(&self, device: &PcapDevice) -> bool {
        if self.names.is_empty() {
            return true;
        }

        self.names.iter().any(|name| {
            device.name == *name
                || device
                    .desc
                    .as_ref()
                    .is_some_and(|desc| desc.eq_ignore_ascii_case(name) || desc.contains(name))
        })
    }
}

pub struct FilteredPcapBackend {
    filter: PcapDeviceFilter,
}

impl FilteredPcapBackend {
    pub fn new(device_names: Vec<String>) -> Self {
        Self {
            filter: PcapDeviceFilter::new(device_names),
        }
    }
}

pub struct PcapCapture {
    capture: Capture<Active>,
    device: PcapDevice,
    id: u64,
    linktype: Linktype,
}

impl CaptureBackend for PcapBackend {
    type Device = PcapDevice;

    fn list_devices(&self) -> Result<Vec<Self::Device>> {
        connected_capture_devices()
    }
}

impl CaptureBackend for FilteredPcapBackend {
    type Device = PcapDevice;

    fn list_devices(&self) -> Result<Vec<Self::Device>> {
        Ok(connected_capture_devices()?
            .into_iter()
            .filter(|device| self.filter.matches(device))
            .collect())
    }
}

pub fn connected_capture_devices() -> Result<Vec<PcapDevice>> {
    Ok(PcapDevice::list()
        .map_err(|e| CaptureError::DeviceError(Box::new(e)))?
        .into_iter()
        .filter(|d| matches!(d.flags.connection_status, pcap::ConnectionStatus::Connected) || d.name.starts_with("rvi"))
        .filter(|d| !d.addresses.is_empty() || d.name.starts_with("rvi"))
        .filter(|d| !d.flags.is_loopback())
        .collect::<Vec<_>>())
}

impl CaptureDevice for PcapDevice {
    type Capture = PcapCapture;

    fn name(&self) -> &str {
        &self.name
    }

    fn create_capture(&self) -> Result<Self::Capture> {
        let mut capture = Capture::from_device(self.clone())
            .map_err(|e| CaptureError::DeviceError(Box::new(e)))?
            .immediate_mode(true)
            .timeout(1000)
            .buffer_size(1024 * 1024 * 16) // 16MB
            .open()
            .map_err(|e| CaptureError::CaptureError {
                has_captured: false,
                error: Box::new(e),
            })?;

        let mut capture = capture.setnonblock().map_err(|e| CaptureError::CaptureError {
            has_captured: false,
            error: Box::new(e),
        })?;

        capture
            .filter(PCAP_FILTER, true)
            .map_err(|e| CaptureError::FilterError(Box::new(e)))?;
        let linktype = capture.get_datalink();

        let mut hasher = DefaultHasher::new();
        self.name.hash(&mut hasher);
        let id = hasher.finish();

        Ok(PcapCapture {
            capture,
            device: self.clone(),
            id,
            linktype,
        })
    }
}

pub struct Codec {
    source_id: u64,
    linktype: Linktype,
}

impl PacketCodec for Codec {
    type Item = Packet;

    fn decode(&mut self, pkt: pcap::Packet) -> Self::Item {
        Packet {
            source_id: self.source_id,
            data: normalize_link_payload(pkt.data, self.linktype),
        }
    }
}

fn normalize_link_payload(data: &[u8], linktype: Linktype) -> Vec<u8> {
    let payload = if linktype == Linktype::PKTAP || looks_like_pktap_payload(data) {
        strip_pktap_payload(data)
    } else {
        data
    };

    normalize_raw_ip_payload(payload)
}

fn looks_like_pktap_payload(data: &[u8]) -> bool {
    let Some(header_len) = pktap_header_len(data) else {
        return false;
    };

    header_len < data.len() && data.get(4..8) == Some(&[1, 0, 0, 0])
}

fn pktap_header_len(data: &[u8]) -> Option<usize> {
    let bytes = data.get(..4)?;
    let header_len = u32::from_le_bytes(bytes.try_into().ok()?) as usize;
    if header_len < 32 {
        return None;
    }

    Some(header_len)
}

fn strip_pktap_payload(data: &[u8]) -> &[u8] {
    let Some(header_len) = pktap_header_len(data) else {
        return data;
    };
    if header_len >= data.len() {
        return data;
    }

    &data[header_len..]
}

fn normalize_raw_ip_payload(data: &[u8]) -> Vec<u8> {
    let Some(first) = data.first() else {
        return Vec::new();
    };

    let ethertype = match first >> 4 {
        4 => [0x08, 0x00],
        6 => [0x86, 0xdd],
        _ => return data.to_vec(),
    };

    let mut ethernet = Vec::with_capacity(data.len() + 14);
    ethernet.extend_from_slice(&[0; 12]);
    ethernet.extend_from_slice(&ethertype);
    ethernet.extend_from_slice(data);
    ethernet
}

impl PacketCapture for PcapCapture {
    #[instrument(skip_all, fields(device = self.device.desc))]
    fn capture_packets(mut self) -> Result<impl Stream<Item = Result<Packet>>> {
        let mut has_captured = false;

        return match self.capture.stream(Codec {
            source_id: self.id,
            linktype: self.linktype,
        }) {
            Ok(stream) => Ok(Box::pin(
                stream
                    .take_while(move |r| {
                        let result = match &r {
                            Err(pcap::Error::PcapError(error_msg)) => {
                                // Check if this is a device removal error
                                if error_msg.contains("ERROR_DEVICE_REMOVED") {
                                    warn!(%error_msg, %self.device.name, "Device removed, terminating capture stream");
                                    false // Stop the stream immediately
                                } else {
                                    true // Continue for other errors
                                }
                            }
                            _ => true, // Continue for Ok packets
                        };

                        async move { result }
                    })
                    .map(move |r| match r {
                        Ok(p) => {
                            has_captured = true;
                            Ok(p)
                        }
                        Err(e) => Err(CaptureError::CaptureError {
                            has_captured,
                            error: Box::new(e),
                        }),
                    }),
            )),
            Err(e) => Err(CaptureError::CaptureError {
                has_captured: false,
                error: Box::new(e),
            }),
        };
    }
}
