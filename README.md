# Issue
We are using Envoy within our Organisation and are using mutual TLS authentication to protect applications.

With an upgrade of Envoy from version 1.30.X+ to 1.31.X+), BoringSSL was updated to version hash (`2db0eb3f96a5756298dcd7f9319e56a98585bd10` - pulled from https://github.com/google/boringssl/archive/2db0eb3f96a5756298dcd7f9319e56a98585bd10.tar.gz - see (https://github.com/envoyproxy/envoy/commit/aecb9bbb64fe5aa5d923ea10199a24574b289087).

After running this version of Envoy, we started to encounter an issue as described in https://github.com/envoyproxy/envoy/issues/37207 , whereby the mutual TLS requests began to fail for some of our Certificate Authorities.

Within the github issue, a change within BoringSSL was highlighted (by `[ggreenway](https://github.com/ggreenway)`), namely  (https://github.com/google/boringssl/commit/580c04109e8a63d08582b3d948cf54849371a73e#diff-2a76d0a7ddc5ae2646a6c183270a7b4d5302d8491acb0af0dfbd70643efdf431R1242).

We have put together a sample Root CA, Intermedia CA and Client Certificate (issued by the Intermediate) which has a reproduction case, based on a setup internally and also is similar to `www.google.com`, it’s intermediate `WR2` and the root `GTS Root R1`.

The WR2 CA embeds a link to the CRL issued by the root, and the www.google.com certificate embeds a link to the CRL issued by the intermediate. We have replicated those CAs and CRLs, and adjusted the www.google.com certificate to become a client certificate. Hopefully this shows that the issue could also affect Google and other services.

Below, we have provided a reproduction case whereby when validating the Certificates (full trust store of Root + Intermediate) and checking CRLs, a ‘Different CRL Scope’ error message is returned, but only when the CRL IDP Extension is present.

There are 2 sets of configuration:

- Leaf certificate with an Intermediate CRL **with** the CRL IDP Extension
- Leaf certificate with an Intermediate CRL **without** the CRL IDP Extension

The CRL without the extension validates successfully.

Can you validate if this is actually an issue in BoringSSL, or are we missing some configuration within our CA setup.

Much appreciated

# Reproduction Case

Clone & Build BoringSSL

    git clone https://boringssl.googlesource.com/boringssl
    cd boringssl
    mkdir build && cd build
    cmake ..
    make


# Test Code / Bundle

    # Clone this repository
    git clone https://github.com/acarlson0000/boringssl-crl-test.git

    # Set up Certificate Bundles
    cd make-certificates

    # To create the bundles with CRL IDP Extension
    make with-idp

    # To create the bundles without CRL IDP Extension
    make without-idp

    # Run Test Code
    # Make sure to update CGO_LDFLAGS with the correct path to your boringssl build:
    export CGO_LDFLAGS="-L$(pwd)/boringssl/build -lssl -lcrypto"
    go run verify_cert_and_crl.go <client.crt> <ca_chain.crt> <ca_bundle.crl>

eg.

  # With CRL IDP Extension

    export CGO_LDFLAGS="-L$(pwd)/boringssl/build -lssl -lcrypto"
    go run verify_cert_and_crl.go boringssl-test/make-certificates/with-idp/leaf.crt boringssl-test/make-certificates/with-idp/ca-chain.crt boringssl-test/make-certificates/with-idp/ca-bundle.crl
    # command-line-arguments
    ld: warning: ignoring duplicate libraries: '-lcrypto', '-lssl'
    Validation failed: certificate verification failed: Different CRL scope (error code: 44)

  # Without CRL IDP Extension

    export CGO_LDFLAGS="-L$(pwd)/boringssl/build -lssl -lcrypto"
    go run verify_cert_and_crl.go boringssl-test/make-certificates/without-idp/leaf.crt boringssl-test/make-certificates/without-idp/ca-chain.crt boringssl-test/make-certificates/without-idp/ca-bundle.crl
    # command-line-arguments
    ld: warning: ignoring duplicate libraries: '-lcrypto', '-lssl'
    Certificate is valid and has not been revoked!
    Client certificate is valid against the CA trust store and CRLs.
