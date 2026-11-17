//! Executable dependency probes for the native worker port.

#[cfg(test)]
mod tests {
    use hpack::Decoder;
    use httlib_hpack::Decoder as BoundedDecoder;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use rustls::RootCertStore;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    use std::sync::Arc;

    /// Check retained indexes, Huffman strings, malformed data, and table limits.
    #[test]
    fn hpack_decoder_feasibility() {
        let mut decoder = Decoder::new();
        let inserted = vec![(b"foo".to_vec(), b"bar".to_vec())];
        assert_eq!(decoder.decode(b"\x40\x03foo\x03bar").unwrap(), inserted);
        assert_eq!(decoder.decode(b"\xbe").unwrap(), inserted);
        let mut fresh = Decoder::new();
        let huffman = fresh
            .decode(b"\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff")
            .unwrap();
        assert!(huffman.contains(&(b":authority".to_vec(), b"www.example.com".to_vec())));
        assert!(fresh.decode(b"\x80").is_err());
        fresh.set_max_table_size(0);
        // hpack 0.3.0 accepts a size update above the configured limit.
        assert!(fresh.decode(b"\x3f\xe2\x1f").is_ok());
    }

    /// Check the bounded alternative against the same state and Huffman bytes.
    #[test]
    fn bounded_hpack_decoder_feasibility() {
        let mut decoder = BoundedDecoder::with_dynamic_size(4096);
        let mut headers = Vec::new();
        decoder
            .decode(&mut b"\x40\x03foo\x03bar".to_vec(), &mut headers)
            .unwrap();
        assert_eq!(
            (headers[0].0.as_slice(), headers[0].1.as_slice()),
            (b"foo".as_slice(), b"bar".as_slice())
        );
        headers.clear();
        decoder.decode(&mut b"\xbe".to_vec(), &mut headers).unwrap();
        assert_eq!(
            (headers[0].0.as_slice(), headers[0].1.as_slice()),
            (b"foo".as_slice(), b"bar".as_slice())
        );
        let mut fresh = BoundedDecoder::with_dynamic_size(4096);
        headers.clear();
        fresh
            .decode(
                &mut b"\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"
                    .to_vec(),
                &mut headers,
            )
            .unwrap();
        assert!(
            headers
                .iter()
                .any(|(name, value, _)| name == b":authority" && value == b"www.example.com")
        );
        assert!(
            fresh
                .decode(&mut b"\x80".to_vec(), &mut Vec::new())
                .is_err()
        );
        fresh.set_max_dynamic_size(0);
        assert!(
            fresh
                .decode(&mut b"\x3f\xe2\x1f".to_vec(), &mut Vec::new())
                .is_err()
        );
    }

    /// Check the locked rustls verifier with a fixture CA and wrong-host rejection.
    #[test]
    fn certificate_chain_and_hostname() {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_params = CertificateParams::new(vec!["fixture.example".to_owned()]).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let host = ServerName::try_from("fixture.example").unwrap();
        assert!(
            verifier
                .verify_server_cert(leaf.der(), &[], &host, &[], UnixTime::now())
                .is_ok()
        );
        let wrong = ServerName::try_from("other.example").unwrap();
        assert!(
            verifier
                .verify_server_cert(leaf.der(), &[], &wrong, &[], UnixTime::now())
                .is_err()
        );
        assert!(
            WebPkiServerVerifier::builder(Arc::new(RootCertStore::empty()))
                .build()
                .is_err()
        );
        let other_ca_key = KeyPair::generate().unwrap();
        let mut other_ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        other_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let other_ca = other_ca_params.self_signed(&other_ca_key).unwrap();
        let mut other_roots = RootCertStore::empty();
        other_roots.add(other_ca.der().clone()).unwrap();
        let other_verifier = WebPkiServerVerifier::builder(Arc::new(other_roots))
            .build()
            .unwrap();
        assert!(
            other_verifier
                .verify_server_cert(leaf.der(), &[], &host, &[], UnixTime::now())
                .is_err()
        );
    }
}
