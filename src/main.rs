use crate::{
    args::Args,
    utils::{
        get_received_data_ranges, get_sent_data_ranges, redact_and_reveal_received_data,
        redact_and_reveal_sent_data,
    },
};
use clap::Parser as ClapParser;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use thiserror::Error;

use http_body_util::Empty;
use hyper::{StatusCode, Version, body::Bytes};
use hyper_util::rt::TokioIo;
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{
    CryptoProvider, Secrets,
    attestation::Attestation,
    presentation::{Presentation, PresentationOutput},
    request::RequestConfig,
    signing::VerifyingKey,
    transcript::TranscriptCommitConfig,
};
use tlsn_prover::{Prover, ProverConfig};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::Level;

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

pub mod args;
pub mod ast;
pub mod request;
pub mod response;
pub mod utils;

#[derive(Debug, Clone)]
pub struct AppState {
    pub server_domain: String,
    pub server_port: u16,
    pub server_addr: SocketAddr,
    pub notary_host: String,
    pub notary_port: u16,
    pub max_sent_data: usize,
    pub max_recv_data: usize,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("Invalid socket address: {0}")]
    InvalidSocketAddress(String),
}

impl AppState {
    pub fn new(args: &args::Args) -> Result<Self, AppError> {
        let server_ip: IpAddr = args
            .server_addr
            .parse()
            .map_err(|_| AppError::InvalidIpAddress(args.server_addr.clone()))?;

        let server_addr = SocketAddr::new(server_ip, args.server_port);

        Ok(AppState {
            server_domain: args.server_domain.clone(),
            server_port: args.server_port,
            server_addr,
            notary_host: args.notary_host.clone(),
            notary_port: args.notary_port,
            max_sent_data: args.max_sent_data,
            max_recv_data: args.max_recv_data,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let args = Args::parse();
    let app_state = AppState::new(&args)?;

    let uri = format!(
        "https://{}:{}/api/retail/transaction/6",
        app_state.server_domain,
        app_state.server_addr.port()
    );

    println!("Notarizing");

    let (attestation, secrets) = notarize(&uri, vec![], &app_state).await?;
    println!("Notarized");

    let presentation = create_presentation(attestation, secrets).await?;
    println!("Presentation created");

    verify_presentation(presentation).await?;
    println!("Presentation verified");

    Ok(())
}

async fn notarize(
    uri: &str,
    extra_headers: Vec<(&str, &str)>,
    app_state: &AppState,
) -> Result<(Attestation, Secrets), Box<dyn std::error::Error>> {
    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(&app_state.notary_host)
        .port(app_state.notary_port)
        .enable_tls(false)
        .build()
        .unwrap();

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(app_state.max_sent_data)
        .max_recv_data(app_state.max_recv_data)
        .build()?;

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("Could not connect to notary. Make sure it is running.");

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(
            include_bytes!("./certs/rootCA.der").to_vec(),
        ))
        .unwrap();
    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let prover_config = ProverConfig::builder()
        .server_name("localhost")
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(app_state.max_sent_data)
                .max_recv_data(app_state.max_recv_data)
                .build()?,
        )
        .crypto_provider(crypto_provider)
        .build()?;

    print!("Prover config set");
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    let client_socket = tokio::net::TcpStream::connect(("localhost", 3001)).await?;

    println!("Connected to server");

    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    println!("MPC connect");

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    tokio::spawn(connection);

    let request_builder = hyper::Request::builder()
        .version(Version::HTTP_11)
        .uri(uri)
        .header("Host", "localhost")
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("Content-Length", "0")
        .header("User-Agent", USER_AGENT)
        .header("x-device-id", "1234567890")
        .header("cookie", "1234567890");

    let mut request_builder = request_builder;
    for (key, value) in extra_headers {
        request_builder = request_builder.header(key, value);
    }
    let request = request_builder.body(Empty::<Bytes>::new())?;

    println!("Starting an MPC TLS connection with the server");

    let response = request_sender.send_request(request).await?;

    println!("Got a response from the server: {:?}", response);

    assert!(response.status() == StatusCode::OK);

    // The prover task should be done now, so we can await it.
    let prover = prover_task.await??;

    // Parse the transcript using your custom parsers to get ranges
    let (prover, recv_ranges) = redact_and_reveal_received_data(prover).await;
    let (mut prover, sent_ranges) = redact_and_reveal_sent_data(prover).await;

    // Commit to the transcript using your custom ranges
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // Commit the ranges identified by your parsing functions
    for range in &recv_ranges {
        builder.commit_recv(range)?;
    }

    for range in &sent_ranges {
        builder.commit_sent(range)?;
    }

    let transcript_commit = builder.build()?;

    // Build an attestation request.
    let mut builder = RequestConfig::builder();
    builder.transcript_commit(transcript_commit);
    let request_config = builder.build()?;

    #[allow(deprecated)]
    let (attestation, secrets) = prover.notarize(&request_config).await?;

    println!("Notarization complete!");

    Ok((attestation, secrets))
}

async fn create_presentation(
    attestation: Attestation,
    secrets: Secrets,
) -> Result<Presentation, Box<dyn std::error::Error>> {
    let recv_ranges = get_received_data_ranges(&secrets);
    let sent_ranges = get_sent_data_ranges(&secrets);

    // Build a transcript proof.
    let mut builder = secrets.transcript_proof_builder();

    // Reveal the ranges identified by your parsing functions
    for range in &recv_ranges {
        builder.reveal_recv(range)?;
    }

    for range in &sent_ranges {
        builder.reveal_sent(range)?;
    }

    let transcript_proof = builder.build()?;

    // Use default crypto provider to build the presentation.
    let provider = CryptoProvider::default();

    let mut builder = attestation.presentation_builder(&provider);

    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    let presentation: Presentation = builder.build()?;

    println!("Presentation built successfully!");

    Ok(presentation)
}

async fn verify_presentation(presentation: Presentation) -> Result<(), Box<dyn std::error::Error>> {
    // Create a crypto provider accepting the server-fixture's self-signed
    // root certificate.
    //
    // This is only required for offline testing with the server-fixture. In
    // production, use `CryptoProvider::default()` instead.
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(
            include_bytes!("./certs/rootCA.der").to_vec(),
        ))
        .unwrap();
    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let VerifyingKey {
        alg,
        data: key_data,
    } = presentation.verifying_key();

    println!(
        "Verifying presentation with {alg} key: {}\n\n**Ask yourself, do you trust this key?**\n",
        hex::encode(key_data)
    );

    // Verify the presentation.
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        // extensions, // Optionally, verify any custom extensions from prover/notary.
        ..
    } = presentation.verify(&crypto_provider).unwrap();

    // The time at which the connection was started.
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
    let server_name = server_name.unwrap();
    let mut partial_transcript = transcript.unwrap();
    // Set the unauthenticated bytes so they are distinguishable.
    partial_transcript.set_unauthed(b'X');

    let sent = String::from_utf8_lossy(partial_transcript.sent_unsafe());
    let recv = String::from_utf8_lossy(partial_transcript.received_unsafe());

    println!("-------------------------------------------------------------------");
    println!(
        "Successfully verified that the data below came from a session with {server_name} at {time}.",
    );
    println!("Note that the data which the Prover chose not to disclose are shown as X.\n");
    println!("Data sent:\n");
    println!("{}\n", sent);
    println!("Data received:\n");
    println!("{}\n", recv);
    println!("-------------------------------------------------------------------");

    Ok(())
}
