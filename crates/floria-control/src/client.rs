use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::protocol::{
    read_msg, write_msg, ControlCommand, ControlOutcome, ControlRequest, ControlResponse,
    ControlResult,
};

pub struct ControlClient {
    stream: UnixStream,
    next_request_id: u64,
}

impl ControlClient {
    pub fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        Ok(ControlClient { stream, next_request_id: 1 })
    }

    pub fn request(&mut self, command: ControlCommand) -> io::Result<ControlResult> {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        write_msg(&mut self.stream, &ControlRequest { request_id, command })?;
        let response: ControlResponse = read_msg(&mut self.stream)?;
        if response.request_id != request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "control response id {} does not match request {request_id}",
                    response.request_id
                ),
            ));
        }
        match response.outcome {
            ControlOutcome::Ok { result } => Ok(result),
            ControlOutcome::Error { error } => Err(io::Error::other(format!(
                "control {}: {}",
                error.code, error.message
            ))),
        }
    }
}
