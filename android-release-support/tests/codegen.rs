use std::env;
use std::fmt::Write;
use std::fs;

use webpki_ccadb::{crl_hosts, RootStore};

/// Regenerates the Android network security config listing hosts that serve CRLs.
///
/// The generated file is checked in; this test fails with a diff whenever the
/// data returned by CCADB no longer matches it.
///
/// Note that this reaches out to the network to query the CCADB.
#[ignore] // Ignored by default because it requires network access and is slow.
#[tokio::test]
async fn update_security_config() -> Result<(), Box<dyn std::error::Error>> {
    let mut hosts = crl_hosts(RootStore::Chrome)
        .await?
        .into_iter()
        .collect::<Vec<_>>();
    hosts.sort();

    let mut out = String::from(HEADER);
    for host in hosts {
        writeln!(
            out,
            "    <domain includeSubdomains=\"true\">{host}</domain>"
        )
        .unwrap();
    }
    out.push_str(FOOTER);

    let stored = fs::read_to_string(OUTPUT).unwrap_or_default();
    fs::write(OUTPUT, &out)?;
    if stored != out {
        println!("run `cargo test --manifest-path android-release-support/Cargo.toml --test codegen -- --ignored` to update the checked-in file");
        similar_asserts::assert_eq!(stored, out);
    }

    Ok(())
}

const HEADER: &str = "\
<?xml version=\"1.0\" encoding=\"utf-8\"?>
<network-security-config>
  <base-config cleartextTrafficPermitted=\"false\" />
  <!-- Some certificate authorities publish signed revocation lists over HTTP.
       The native verifier must be able to fetch these over cleartext to check
       the revocation status of certificates in their chains. This list is
       generated from ccadb by tests/codegen.rs.
       https://github.com/rustls/rustls-platform-verifier/issues/221 -->
  <domain-config cleartextTrafficPermitted=\"true\">
";

const FOOTER: &str = "\
  </domain-config>
</network-security-config>
";

const OUTPUT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../android/rustls-platform-verifier/src/main/res/xml/network_security_config.xml"
);
