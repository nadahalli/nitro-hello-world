// enclave/main.go
package main

import (
	"encoding/binary" // For reading/writing document length
	"fmt"
	"log"
	"time"

	nsm "github.com/hf/nsm"           // For NSM interactions
	"github.com/hf/nsm/request"      // For NSM attestation request structure
	"github.com/mdlayher/vsock"      // For vsock communication
)

const (
	parentCID  = 3    // CID of the parent instance (host). Default is 3 for the host.
	parentPort = 5000 // Port to communicate with on the parent instance.
)

func main() {
	log.Println("Enclave: --- Starting Go Enclave main function ---")
	log.Println("Enclave: Hello from the Go Enclave!")

	// Give the enclave a moment to initialize and for nitro-cli to connect
	time.Sleep(10 * time.Second) // Increased sleep time for more visibility
	log.Println("Enclave: After initial sleep, proceeding with attestation...")

	// 1. Get Attestation Document from NSM
	attestationDoc, err := getAttestationDocument()
	if err != nil {
		log.Fatalf("Enclave: Failed to get attestation document: %v", err)
	}
	log.Println("Enclave: Successfully obtained attestation document.")

	// 2. Establish vsock connection to the parent instance
	// CID 3 is the host machine. The port should match the listener on the host.
	conn, err := vsock.Dial(uint32(parentCID), uint32(parentPort), nil) // Corrected vsock.Dial arguments
	if err != nil {
		log.Fatalf("Enclave: Failed to dial vsock to parent CID %d Port %d: %v", parentCID, parentPort, err)
	}
	defer conn.Close()
	log.Printf("Enclave: Successfully connected to parent via vsock (CID %d, Port %d)\n", parentCID, parentPort)

	// 3. Send Attestation Document over vsock
	// We'll send the length first (4 bytes, Big Endian), then the document bytes
	docLen := uint32(len(attestationDoc))
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, docLen) // Use binary.BigEndian for robustness

	if _, err := conn.Write(lenBytes); err != nil {
		log.Fatalf("Enclave: Failed to send attestation document length: %v", err)
	}
	log.Printf("Enclave: Sent attestation document length: %d bytes\n", docLen)

	if _, err := conn.Write(attestationDoc); err != nil {
		log.Fatalf("Enclave: Failed to send attestation document: %v", err)
	}
	log.Println("Enclave: Attestation document sent successfully.")

	log.Println("Enclave: Finished sending data. Exiting.")
	// The main function will now naturally exit, which causes the enclave to terminate.
}

// getAttestationDocument interacts with the Nitro Secure Module (NSM)
// to retrieve the attestation document.
func getAttestationDocument() ([]byte, error) {
	// Open a session with the NSM device (/dev/nsm)
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("failed to open NSM session: %w", err)
	}
	defer sess.Close()

	// Optional: Add a nonce and user data for stronger attestation
	// A nonce helps prevent replay attacks. User data adds context.
	nonce := []byte(fmt.Sprintf("my-enclave-nonce-%d", time.Now().UnixNano()))
	userData := []byte("hello-world-enclave-data")

	// Create the attestation request
	res, err := sess.Send(&request.Attestation{
		Nonce:    nonce,
		UserData: userData,
		// PublicKey: []byte, // Optional: You can include a public key here for KMS integration
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send attestation request: %w", err)
	}
	if res.Error != "" {
		return nil, fmt.Errorf("NSM returned an error: %s", res.Error)
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, fmt.Errorf("NSM device did not return an attestation document")
	}

	return res.Attestation.Document, nil
}