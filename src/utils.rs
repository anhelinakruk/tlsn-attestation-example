use std::ops::Range;

use pest::Parser;
use tlsn_core::Secrets;
use tlsn_prover::Prover;
use tlsn_prover::state::Committed;

use crate::ast::Searchable;
use crate::request::{Request, RequestParser, Rule as RequestRule};
use crate::response::{Response, ResponseParser, Rule as ResponseRule};

/// Trait for types that provide access to transcript data
pub trait TranscriptProvider {
    fn received_data(&self) -> &[u8];
    fn sent_data(&self) -> &[u8];
}

impl TranscriptProvider for Prover<Committed> {
    fn received_data(&self) -> &[u8] {
        self.transcript().received()
    }

    fn sent_data(&self) -> &[u8] {
        self.transcript().sent()
    }
}

impl TranscriptProvider for Secrets {
    fn received_data(&self) -> &[u8] {
        self.transcript().received()
    }

    fn sent_data(&self) -> &[u8] {
        self.transcript().sent()
    }
}

/// Redacts and reveals received data to the verifier
///
/// # Arguments
/// * `provider` - Object that provides transcript data
///
/// # Returns
/// * `Vec<Range<usize>>` - The ranges to reveal
pub fn get_received_data_ranges<T: TranscriptProvider>(provider: &T) -> Vec<Range<usize>> {
    // Get the received transcript data
    let recv_transcript = provider.received_data();

    // Convert to a UTF-8 string
    let recv_string = match String::from_utf8(recv_transcript.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to convert received data to UTF-8: {}", e);
            return Vec::new();
        }
    };

    println!("Received data: {}", recv_string);

    // Parse the response
    let parse = match ResponseParser::parse(ResponseRule::response, &recv_string) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to parse response: {}", e);
            return Vec::new();
        }
    };

    // Convert the parse result to a Response object
    let response = match Response::try_from(parse) {
        Ok(r) => r,
        Err(e) => {
            println!("Failed to convert parse result to Response: {}", e);
            return Vec::new();
        }
    };

    // Get the ranges to reveal
    response.get_all_ranges_for_keypaths(
        &[
            "state",
            "comment",
            "currency",
            "amount",
            "recipient.account",
            "recipient.username",
            "recipient.code",
            "beneficiary.account",
        ],
        &[],
    )
}

/// Redacts and reveals sent data to the verifier
///
/// # Arguments
/// * `provider` - Object that provides transcript data
///
/// # Returns
/// * `Vec<Range<usize>>` - The ranges to reveal
pub fn get_sent_data_ranges<T: TranscriptProvider>(provider: &T) -> Vec<Range<usize>> {
    // Get the sent transcript data
    let sent_transcript = provider.sent_data();

    // Convert to a UTF-8 string
    let sent_string = match String::from_utf8(sent_transcript.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to convert sent data to UTF-8: {}", e);
            return Vec::new();
        }
    };

    // Parse the request
    let parse = match RequestParser::parse(RequestRule::request, &sent_string) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to parse request: {}", e);
            return Vec::new();
        }
    };

    // Convert the parse result to a Request object
    let request = match Request::try_from(parse) {
        Ok(r) => r,
        Err(e) => {
            println!("Failed to convert parse result to Request: {}", e);
            return Vec::new();
        }
    };

    // Get the ranges to reveal
    request.get_all_ranges_for_keypaths(&[], &["host"])
}

/// Redacts and reveals received data to the verifier (legacy function for Prover)
///
/// # Arguments
/// * `prover` - The prover object to work with
///
/// # Returns
/// * `(Prover<Committed>, Vec<Range<usize>>)` - The prover and the ranges
pub async fn redact_and_reveal_received_data(
    prover: Prover<Committed>,
) -> (Prover<Committed>, Vec<Range<usize>>) {
    let ranges = get_received_data_ranges(&prover);
    (prover, ranges)
}

/// Redacts and reveals sent data to the verifier (legacy function for Prover)
///
/// # Arguments
/// * `prover` - The prover object to work with
///
/// # Returns
/// * `(Prover<Committed>, Vec<Range<usize>>)` - The prover and the ranges
pub async fn redact_and_reveal_sent_data(
    prover: Prover<Committed>,
) -> (Prover<Committed>, Vec<Range<usize>>) {
    let ranges = get_sent_data_ranges(&prover);
    (prover, ranges)
}
