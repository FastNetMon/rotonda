use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use futures::{
    future::{select, Either},
    pin_mut,
};
use routecore::bmp::message::Message as BmpMsg;
use std::{convert::TryInto, io::ErrorKind, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::comms::{Gate, GateStatus, Terminated};

use super::unit::TracingMode;

pub trait FatalError {
    fn is_fatal(&self) -> bool;
}

impl FatalError for std::io::Error {
    fn is_fatal(&self) -> bool {
        match self.kind() {
            std::io::ErrorKind::TimedOut => false,
            std::io::ErrorKind::Interrupted => false,

            std::io::ErrorKind::NotFound => true,
            std::io::ErrorKind::PermissionDenied => true,
            std::io::ErrorKind::ConnectionRefused => true,
            std::io::ErrorKind::ConnectionReset => true,
            std::io::ErrorKind::ConnectionAborted => true,
            std::io::ErrorKind::NotConnected => true,
            std::io::ErrorKind::AddrInUse => true,
            std::io::ErrorKind::AddrNotAvailable => true,
            std::io::ErrorKind::BrokenPipe => true,
            std::io::ErrorKind::AlreadyExists => true,
            std::io::ErrorKind::WouldBlock => true,
            std::io::ErrorKind::InvalidInput => true,
            std::io::ErrorKind::InvalidData => true,
            std::io::ErrorKind::WriteZero => true,
            std::io::ErrorKind::Unsupported => true,
            std::io::ErrorKind::UnexpectedEof => true,
            std::io::ErrorKind::OutOfMemory => true,

            std::io::ErrorKind::Other => false,

            _ => true,
        }
    }
}

/// Smallest legal BMP message size: version(1) + length(4) + type(1).
const MIN_BMP_MSG_LEN: usize = 6;

/// Upper bound we accept for a single BMP message. RFC 7854 imposes no hard
/// cap, but legitimate route-monitoring frames carry a single BGP UPDATE
/// (≤ 65 KB even with extended-length attributes) plus a few hundred bytes
/// of BMP headers. 2 MiB is well above any real-world frame and prevents a
/// malicious or buggy exporter from forcing multi-GiB allocations via the
/// length field.
const MAX_BMP_MSG_LEN: usize = 2 * 1024 * 1024;

/// # Tracing
///
/// If a trace id is found in the incoming message it will be returned in
/// the u8 value as a value greater than zero. A zero value indicates that
/// tracing was not requested.
async fn bmp_read<T: AsyncRead + Unpin>(
    mut rx: T,
    tracing_mode: TracingMode,
) -> Result<(T, Bytes, u8), (T, std::io::Error)> {
    let mut msg_buf = BytesMut::new();
    msg_buf.resize(5, 0u8);
    if let Err(err) = rx.read_exact(&mut msg_buf).await {
        return Err((rx, err));
    }

    // Diagnostics hack: treat the high half of the version byte as a trace id
    // if any bits are set, i.e. it represents an unsigned integer value
    // greater than zero.
    let mut trace_id = 0;

    if tracing_mode != TracingMode::Off {
        trace_id = msg_buf[0] >> 4;
        msg_buf[0] &= 0b0000_1111;
    };

    // Don't call BmpMsg::check() as it requires the rest of the message to have already been read
    let _version = &msg_buf[0];
    let len = u32::from_be_bytes(msg_buf[1..5].try_into().unwrap()) as usize;

    // The length field is attacker-controlled (cleartext BMP TCP). Reject
    // out-of-range values before we resize the buffer: a tiny value would
    // make the `&mut msg_buf[5..]` slice below panic, and an oversized one
    // would let an exporter trigger arbitrary allocations.
    if !(MIN_BMP_MSG_LEN..=MAX_BMP_MSG_LEN).contains(&len) {
        return Err((
            rx,
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "BMP message length {} out of range [{}, {}]",
                    len, MIN_BMP_MSG_LEN, MAX_BMP_MSG_LEN
                ),
            ),
        ));
    }

    msg_buf.resize(len, 0u8);
    if let Err(err) = rx.read_exact(&mut msg_buf[5..]).await {
        return Err((rx, err));
    }

    let msg_buf = msg_buf.freeze();

    match BmpMsg::from_octets(&msg_buf) {
        Ok(_) => Ok((rx, msg_buf, trace_id)),
        Err(err) => Err((rx, std::io::Error::other(err.to_string()))),
    }
}

pub struct BmpStream<T: AsyncRead> {
    rx: Option<T>,
    gate: Gate,
    tracing_mode: Arc<ArcSwap<TracingMode>>,
}

impl<T: AsyncRead + Unpin> BmpStream<T> {
    pub fn new(
        rx: T,
        gate: Gate,
        tracing_mode: Arc<ArcSwap<TracingMode>>,
    ) -> Self {
        Self {
            rx: Some(rx),
            gate,
            tracing_mode,
        }
    }

    /// Retrieve the next BMP message from the stream.
    ///
    /// # Errors
    ///
    /// Returns an [std::io::Error] of the same kind as [AsyncReadExt::read_exact],
    /// i.e. [ErrorKind::UnexpectedEof] if "end of file" is encountered, or
    /// any other read error.
    ///
    /// Additionally it can also return [ErrorKind::Other] if received bytes
    /// are rejected by the BMP parser.
    ///
    /// # Cancel safety
    ///
    /// This function is NOT cancel safe. If cancelled the stream receiver
    /// will be lost and no further updates can be read from the stream.
    ///
    /// # Tracing
    ///
    /// If a trace id is found in the incoming message it will be returned in
    /// the u8 value as a value greater than zero. A zero value indicates that
    /// tracing was not requested.
    pub async fn next(
        &mut self,
    ) -> Result<(Option<Bytes>, Option<GateStatus>, u8), std::io::Error> {
        let mut saved_gate_status = None;

        if let Some(rx) = self.rx.take() {
            let mut update_fut =
                Box::pin(bmp_read(rx, **self.tracing_mode.load()));
            loop {
                let process = self.gate.process();
                pin_mut!(process);

                match select(process, update_fut).await {
                    Either::Left((Err(Terminated), _)) => {
                        // Unit termination signal received
                        // The unit will report this so no need to report it here.
                        return Ok((None, None, 0));
                    }
                    Either::Left((Ok(status), next_fut)) => {
                        // Unit status update received, save it to return with the
                        // next received message so that this router handler can
                        // reconfigure itself if needed.
                        saved_gate_status = Some(status);

                        // The unit will report the status change so no need to
                        // also report it here.

                        update_fut = next_fut;
                    }
                    Either::Right((Err((rx, err)), _)) => {
                        // Error while receiving data.
                        if !err.is_fatal() {
                            self.rx = Some(rx);
                        }
                        return Err(err);
                    }
                    Either::Right((Ok((rx, msg, trace_id)), _)) => {
                        // BMP message received

                        // Save the receiver for the next call to next()
                        self.rx = Some(rx);

                        // Return the message for processing
                        return Ok((Some(msg), saved_gate_status, trace_id));
                    }
                }
            }
        }

        Err(std::io::Error::other(
            "Internal error: no receiver available",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode a 5-byte BMP prefix with a given length field.
    fn header_with_len(len: u32) -> Vec<u8> {
        let mut buf = vec![3u8]; // version
        buf.extend_from_slice(&len.to_be_bytes());
        buf
    }

    /// `bmp_read` against the given byte stream, run on a small tokio runtime.
    fn run_bmp_read(input: Vec<u8>) -> Result<(Bytes, u8), std::io::Error> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let cursor = std::io::Cursor::new(input);
            match bmp_read(cursor, TracingMode::Off).await {
                Ok((_, msg, trace)) => Ok((msg, trace)),
                Err((_, err)) => Err(err),
            }
        })
    }

    #[test]
    fn rejects_length_below_minimum() {
        // len = 4 is below the 6-byte BMP minimum and would have made the
        // historical `&mut msg_buf[5..]` slice panic after resize.
        let err = run_bmp_read(header_with_len(4)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_zero_length() {
        let err = run_bmp_read(header_with_len(0)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_length_above_cap() {
        // The historical code would have called BytesMut::resize with this
        // value, attempting a ~4 GiB allocation.
        let err = run_bmp_read(header_with_len(u32::MAX)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn accepts_frame_within_bounds() {
        // A 6-byte InitiationMessage (type 4) with no TLVs is the smallest
        // legal BMP frame. The routecore parser may or may not accept an
        // empty Initiation depending on its strictness, but in either case
        // our length-check is what we want to verify here: it must NOT
        // reject the frame with ErrorKind::InvalidData.
        let mut input = header_with_len(MIN_BMP_MSG_LEN as u32);
        input.push(4u8); // BMP InitiationMessage
        match run_bmp_read(input) {
            Ok((msg, trace)) => {
                assert_eq!(msg.len(), MIN_BMP_MSG_LEN);
                assert_eq!(trace, 0);
            }
            Err(err) => {
                // Any parse error from routecore is acceptable; what's not
                // acceptable is our own length-validation rejecting a
                // legitimately-sized frame.
                assert_ne!(
                    err.kind(),
                    ErrorKind::InvalidData,
                    "length-check spuriously rejected a {}-byte frame: {}",
                    MIN_BMP_MSG_LEN,
                    err,
                );
            }
        }
    }
}
