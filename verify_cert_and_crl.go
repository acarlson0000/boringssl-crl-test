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
	"strings"
	"unsafe"
)

// loadCertificate loads a single X.509 certificate from a file
func loadCertificate(certPath string) (*C.X509, error) {
	fmt.Printf("Loading certificate from: %s\n", certPath) // Add logging
	cPath := C.CString(certPath)
	defer C.free(unsafe.Pointer(cPath))

	mode := C.CString("r")
	defer C.free(unsafe.Pointer(mode))

	file := C.fopen(cPath, mode)
	if file == nil {
		return nil, fmt.Errorf("failed to open certificate file: %s", certPath)
	}
	defer C.fclose(file)

	cert := C.PEM_read_X509(file, nil, nil, nil)
	if cert == nil {
		return nil, fmt.Errorf("failed to read certificate from: %s", certPath)
	}
	return cert, nil
}

// loadCertificates loads multiple X.509 certificates from one or more files
func loadCertificates(paths []string) (*C.STACK_OF_X509, error) {
	fmt.Printf("Loading CA certificates from paths: %v\n", paths) // Add logging
	stack := C.sk_X509_new_null()
	if stack == nil {
		return nil, fmt.Errorf("failed to create X509 stack")
	}

	for _, path := range paths {
		cPath := C.CString(path)
		defer C.free(unsafe.Pointer(cPath))

		mode := C.CString("r")
		defer C.free(unsafe.Pointer(mode))

		file := C.fopen(cPath, mode)
		if file == nil {
			return nil, fmt.Errorf("failed to open cert file: %s", path)
		}
		defer C.fclose(file)

		for {
			cert := C.PEM_read_X509(file, nil, nil, nil)
			if cert == nil {
				break
			}
			C.sk_X509_push(stack, cert)
		}
	}
	return stack, nil
}

// loadCRLs loads multiple CRLs from one or more files
func loadCRLs(paths []string) ([]*C.X509_CRL, error) {
	fmt.Printf("Loading CRLs from paths: %v\n", paths) // Add logging
	var crls []*C.X509_CRL

	for _, path := range paths {
		cPath := C.CString(path)
		defer C.free(unsafe.Pointer(cPath))

		mode := C.CString("r")
		defer C.free(unsafe.Pointer(mode))

		file := C.fopen(cPath, mode)
		if file == nil {
			return nil, fmt.Errorf("failed to open CRL file: %s", path)
		}
		defer C.fclose(file)

		for {
			crl := C.PEM_read_X509_CRL(file, nil, nil, nil)
			if crl == nil {
				break
			}
			crls = append(crls, crl)
		}
	}
	return crls, nil
}

// validateCertificate verifies the client certificate using CA bundle and CRLs
func validateCertificate(certPath string, caPaths []string, crlPaths []string) error {
	fmt.Println("Starting certificate validation...") // Add logging

	clientCert, err := loadCertificate(certPath)
	if err != nil {
		return fmt.Errorf("error loading client certificate: %v", err)
	}
	defer C.X509_free(clientCert)
	fmt.Println("Client certificate loaded successfully.") // Add logging

	caCerts, err := loadCertificates(caPaths)
	if err != nil {
		return fmt.Errorf("error loading CA certificates: %v", err)
	}
	defer C.sk_X509_free(caCerts)
	fmt.Println("CA certificates loaded successfully.") // Add logging

	crls, err := loadCRLs(crlPaths)
	if err != nil {
		return fmt.Errorf("error loading CRLs: %v", err)
	}
	defer func() {
		for _, crl := range crls {
			C.X509_CRL_free(crl)
		}
	}()
	fmt.Println("CRLs loaded successfully.") // Add logging

	store := C.X509_STORE_new()
	if store == nil {
		return fmt.Errorf("failed to create X509_STORE")
	}
	defer C.X509_STORE_free(store)
	fmt.Println("X509_STORE created successfully.") // Add logging

	// Add CA certs to store
	for i := C.int(0); i < C.int(C.sk_X509_num(caCerts)); i++ {
		ca := C.sk_X509_value(caCerts, C.size_t(i))
		if C.X509_STORE_add_cert(store, ca) != 1 {
			C.ERR_print_errors_fp(C.stderr)
			return fmt.Errorf("failed to add CA cert to store")
		}
	}
	fmt.Println("CA certificates added to X509_STORE.") // Add logging

	// Add CRLs to store
	for _, crl := range crls {
		if C.X509_STORE_add_crl(store, crl) != 1 {
			C.ERR_print_errors_fp(C.stderr)
			return fmt.Errorf("failed to add CRL to store")
		}
	}
	fmt.Println("CRLs added to X509_STORE.") // Add logging

	C.X509_STORE_set_flags(store, C.X509_V_FLAG_CRL_CHECK|C.X509_V_FLAG_CRL_CHECK_ALL)
	fmt.Println("CRL check flags set on X509_STORE.") // Add logging

	ctx := C.X509_STORE_CTX_new()
	if ctx == nil {
		return fmt.Errorf("failed to create X509_STORE_CTX")
	}
	defer C.X509_STORE_CTX_free(ctx)
	fmt.Println("X509_STORE_CTX created successfully.") // Add logging

	if C.X509_STORE_CTX_init(ctx, store, clientCert, nil) != 1 {
		C.ERR_print_errors_fp(C.stderr)
		return fmt.Errorf("failed to initialize verification context")
	}
	fmt.Println("X509_STORE_CTX initialized successfully.") // Add logging

	result := C.X509_verify_cert(ctx)
	if result != 1 {
		errCode := C.X509_STORE_CTX_get_error(ctx)
		errStr := C.X509_verify_cert_error_string(C.long(errCode))
		fmt.Printf("Verification error code: %d, error string: %s\n", errCode, C.GoString(errStr)) // Add logging
		return fmt.Errorf("certificate verification failed: %s (error code: %d)", C.GoString(errStr), errCode)
	}

	fmt.Println("Certificate is valid and has not been revoked.") // Add logging
	return nil
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: go run verify_cert_and_crl.go <leaf_cert.pem> <ca1.pem,ca2.pem,...> <crl1.pem,crl2.pem,...>")
		return
	}

	certPath := os.Args[1]
	caPaths := strings.Split(os.Args[2], ",")
	crlPaths := strings.Split(os.Args[3], ",")

	if err := validateCertificate(certPath, caPaths, crlPaths); err != nil {
		fmt.Printf("Validation failed: %v\n", err)
	} else {
		fmt.Println("Client certificate is valid against CA chain and CRLs.")
	}
}
