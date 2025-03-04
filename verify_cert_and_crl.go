package main

/*
#cgo CFLAGS: -I./boringssl/include
#cgo LDFLAGS: -L./boringssl/build -lssl -lcrypto
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/safestack.h>  // Required for STACK_OF macros
#include <stdlib.h>

typedef STACK_OF(X509) STACK_OF_X509;  // Define the type explicitly

*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

// loadCertificate loads a single X.509 certificate from a file
func loadCertificate(certPath string) (*C.X509, error) {
	certFile := C.CString(certPath)
	defer C.free(unsafe.Pointer(certFile))

	file := C.fopen(certFile, C.CString("r"))
	if file == nil {
		return nil, fmt.Errorf("failed to open certificate file: %s", certPath)
	}
	defer C.fclose(file)

	cert := C.PEM_read_X509(file, nil, nil, nil)
	if cert == nil {
		return nil, fmt.Errorf("failed to load certificate from: %s", certPath)
	}
	return cert, nil
}

// loadCertificates loads a stack of X.509 certificates from a chain file (CA bundle)
func loadCertificates(certPath string) (*C.STACK_OF_X509, error) {
	certFile := C.CString(certPath)
	defer C.free(unsafe.Pointer(certFile))

	file := C.fopen(certFile, C.CString("r"))
	if file == nil {
		return nil, fmt.Errorf("failed to open certificate file: %s", certPath)
	}
	defer C.fclose(file)

	certs := C.sk_X509_new_null()
	if certs == nil {
		return nil, fmt.Errorf("failed to create X509 stack")
	}

	for {
		cert := C.PEM_read_X509(file, nil, nil, nil)
		if cert == nil {
			break
		}
		C.sk_X509_push(certs, cert)
	}

	return certs, nil
}

// loadCRL loads a CRL (Certificate Revocation List) from a file
func loadCRL(crlPath string) (*C.X509_CRL, error) {
	crlFile := C.CString(crlPath)
	defer C.free(unsafe.Pointer(crlFile))

	file := C.fopen(crlFile, C.CString("r"))
	if file == nil {
		return nil, fmt.Errorf("failed to open CRL file: %s", crlPath)
	}
	defer C.fclose(file)

	crl := C.PEM_read_X509_CRL(file, nil, nil, nil)
	if crl == nil {
		return nil, fmt.Errorf("failed to load CRL from: %s", crlPath)
	}
	return crl, nil
}

// validateCertificate verifies the client certificate against a CA and checks CRL
func validateCertificate(certPath, caCertPath, crlPath string) error {
	// Load client certificate
	clientCert, err := loadCertificate(certPath)
	if err != nil {
		return err
	}
	defer C.X509_free(clientCert)

	// Load CA certificates (full chain)
	caCerts, err := loadCertificates(caCertPath)
	if err != nil {
		return err
	}
	defer C.sk_X509_free(caCerts)

	// Load CRL
	crl, err := loadCRL(crlPath)
	if err != nil {
		return err
	}
	defer C.X509_CRL_free(crl)

	// Create a new X.509 trust store
	store := C.X509_STORE_new()
	if store == nil {
		return fmt.Errorf("failed to create X509_STORE")
	}
	defer C.X509_STORE_free(store)

	// Add each CA certificate in the chain to the store
	numCerts := C.sk_X509_num(caCerts)
	for i := C.int(0); i < numCerts; i++ {
		caCert := C.sk_X509_value(caCerts, i)
		if C.X509_STORE_add_cert(store, caCert) != 1 {
			return fmt.Errorf("failed to add CA certificate to trust store")
		}
	}

	// Add CRL to the store
	if C.X509_STORE_add_crl(store, crl) != 1 {
		return fmt.Errorf("failed to add CRL to trust store")
	}

	// Enable CRL checking
	C.X509_STORE_set_flags(store, C.X509_V_FLAG_CRL_CHECK|C.X509_V_FLAG_CRL_CHECK_ALL)

	// Create a verification context
	ctx := C.X509_STORE_CTX_new()
	if ctx == nil {
		return fmt.Errorf("failed to create X509_STORE_CTX")
	}
	defer C.X509_STORE_CTX_free(ctx)

	// Initialize verification context
	if C.X509_STORE_CTX_init(ctx, store, clientCert, nil) != 1 {
		return fmt.Errorf("failed to initialize verification context")
	}

	// Perform certificate verification
	result := C.X509_verify_cert(ctx)
	if result != 1 {
		errCode := C.X509_STORE_CTX_get_error(ctx)
		errStr := C.X509_verify_cert_error_string(C.long(errCode))
		return fmt.Errorf("certificate verification failed: %s (error code: %d)", C.GoString(errStr), errCode)
	}

	fmt.Println("Certificate is valid and has not been revoked!")
	return nil
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: go run validate_cert.go <client_cert.pem> <ca_chain.pem> <crl.pem>")
		return
	}

	clientCertPath := os.Args[1]
	caCertPath := os.Args[2] // Use full CA chain
	crlPath := os.Args[3]

	err := validateCertificate(clientCertPath, caCertPath, crlPath)
	if err != nil {
		fmt.Printf("Validation failed: %v\n", err)
	} else {
		fmt.Println("Client certificate is valid against the CA trust store and CRL.")
	}
}
