use std::{fs, io::Write, iter, net::TcpStream, sync::Arc};

use rustls::crypto::Identity;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore, VecInput};
use rustls_util::Stream;
use webpki_root_certs::TLS_SERVER_ROOT_CERTS;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    let (_, ignored) = roots.add_parsable_certificates(TLS_SERVER_ROOT_CERTS.iter().cloned());
    assert_eq!(ignored, 0, "{ignored} root certificates were ignored");
    let config = Arc::new(
        ClientConfig::builder(Arc::new(rustls_ring::DEFAULT_PROVIDER.clone()))
            .with_root_certificates(roots)
            .with_no_client_auth()?,
    );

    for &host in HOSTS {
        let server_name = ServerName::try_from(host.to_owned())?;
        let mut output = Vec::new();
        let mut conn = config.connect(server_name).build(&mut output)?;
        let mut sock = TcpStream::connect((host, 443))?;
        let mut input = VecInput::default();
        let mut received_plaintext = Vec::new();
        let mut stream = Stream::new(
            &mut input,
            &mut received_plaintext,
            &mut output,
            &mut conn,
            &mut sock,
        );

        eprintln!("connecting to {host}...");
        stream.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())?;
        stream.flush()?;

        let Some(Identity::X509(certs)) = stream
            .conn
            .peer_identity()
            .map(|identity| identity.identity())
        else {
            eprintln!("no certificates received for {host}");
            continue;
        };

        for (i, der) in iter::once(&certs.end_entity)
            .chain(certs.intermediates.iter())
            .enumerate()
        {
            let host_name = host.replace('.', "_");
            let fname = format!(
                "{}/src/tests/verification_real_world/{host_name}_valid_{}.crt",
                env!("CARGO_MANIFEST_DIR"),
                i + 1
            );
            fs::write(&fname, der.as_ref())?;
            eprintln!("wrote certificate to {fname}");
        }
    }

    Ok(())
}

// We use two different CAs for better coverage and...
const HOSTS: &[&str] = &[
    // This host is using EC-based certificates for coverage.
    "letsencrypt.org",
    // This host is using RSA-based certificates for coverage.
    "aws.amazon.com",
];
