// Take a look at the license at the top of the repository in the LICENSE file.

use std::io;
use std::num::ParseIntError;

use thiserror::Error;

/// Represents errors that can occur in the sysinfo crate.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SysInfoError {
    /// Represents an I/O error with its kind and message.
    #[error("I/O error ({kind}): {message}")]
    Io {
        /// The kind of I/O error.
        kind: String,
        /// The error message.
        message: String,
    },
    /// Represents an integer parsing error.
    #[error("Failed to parse int in string: {0}")]
    ParseIntError(String),
}

impl From<io::Error> for SysInfoError {
    fn from(error: io::Error) -> Self {
        let kind = match error.kind() {
            io::ErrorKind::NotFound => "NotFound".to_string(),
            _ => error.kind().to_string(),
        };
        SysInfoError::Io {
            kind,
            message: error.to_string(),
        }
    }
}

impl From<ParseIntError> for SysInfoError {
    fn from(error: ParseIntError) -> Self {
        SysInfoError::ParseIntError(error.to_string())
    }
}
