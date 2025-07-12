# TLSNotary Attestation Example

A TLSNotary example application that creates cryptographic proofs of HTTP communications using custom request/response parsers.

## Prerequisites

- Rust (latest stable version)
- Git

## Setup Instructions

Follow these steps in order to run the complete TLSNotary attestation example:

### 1. Run the Test Server

First, you need to start the test server that will provide the API endpoint.

```bash
# Clone the test server repository
git clone https://github.com/anhelinakruk/test-server.git
cd test-server

# Run the test server (it will start on localhost:3001)
cargo run
```

Keep this terminal open and the server running.

### 2. Run the TLSNotary Notary Server

In a new terminal, set up and run the TLSNotary notary server.

```bash
# Clone the TLSNotary repository
git clone https://github.com/tlsnotary/tlsn.git
cd tlsn

# Navigate to the notary server directory
cd crates/notary/server

# Run the notary server (it will start on localhost:7047)
cargo run --release
```

For more details about the notary server, see the [official documentation](https://github.com/tlsnotary/tlsn/blob/main/crates/notary/server/README.md).

Keep this terminal open and the notary server running.

### 3. Run the Attestation Example

In a third terminal, run the main attestation example application.

```bash
# Navigate to this project directory
cd path/to/tlsn-attestation-example

# Run the attestation example
cargo run
```

## Configuration

The application uses environment variables for configuration. You can set these using command line arguments or environment variables:

### Environment Variables

- `SERVER_DOMAIN` - Target server domain (default: "localhost")
- `SERVER_PORT` - Target server port (default: 3001)
- `SERVER_ADDR` - Target server IP address (default: "127.0.0.1")
- `NOTARY_HOST` - Notary server host (default: "127.0.0.1")
- `NOTARY_PORT` - Notary server port (default: 7047)
- `MAX_SENT_DATA` - Maximum data to send (default: 4096)
- `MAX_RECV_DATA` - Maximum data to receive (default: 16384)

### Command Line Arguments

You can also use command line arguments:

```bash
cargo run -- --notary-host 127.0.0.1 --notary-port 7047 --server-domain localhost --server-port 3001
```
