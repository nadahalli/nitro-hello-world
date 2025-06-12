// host/main.go
package main

import (
	"encoding/binary"
	"encoding/json" // Still useful for marshaling intermediate map to JSON for debugging
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings" // Added for string manipulation
	"time"
	"context"
	"crypto/sha512"
	"encoding/hex"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/mdlayher/vsock"
	"github.com/fxamacker/cbor/v2" // For parsing CBOR attestation document
)

const (
	enclaveEIFPath = "enclave-hello-world.eif" // Name of your built EIF file
	enclaveCID     = 16                        // CID for the enclave. Choose an unused one.
	hostPort       = 5000                      // Port for vsock communication (must match enclave's parentPort)
)

func main() {
	log.Println("Starting parent instance application.")

	// 1. Build the EIF (if not already built)
	buildEIF()

	// 2. Launch the enclave
	// Note: We keep the memory low (64MB) and CPU count to 2 as per previous debugging.
	enclaveID, err := launchEnclave(enclaveEIFPath, enclaveCID)
	if err != nil {
		log.Fatalf("Failed to launch enclave: %v", err)
	}
	log.Printf("Enclave launched with ID: %s, CID: %d\n", enclaveID, enclaveCID)
	defer terminateEnclave(enclaveID) // Ensure enclave is terminated on exit

	// Give the enclave a moment to boot and connect
	time.Sleep(10 * time.Second) // Give enclave more time to start and send

	// 3. Listen for vsock connection from the enclave
	listener, err := vsock.Listen(uint32(hostPort), nil) // Corrected vsock.Listen
	if err != nil {
		log.Fatalf("Failed to listen on vsock port %d: %v", hostPort, err)
	}
	defer listener.Close()
	log.Printf("Listening for enclave connection on vsock Port %d...\n", hostPort)

	// Accept one connection
	conn, err := listener.Accept()
	if err != nil {
		log.Fatalf("Failed to accept vsock connection: %v", err)
	}
	defer conn.Close()
	log.Println("Enclave connected!")

	// 4. Receive the attestation document
	attestationDoc, err := receiveAttestationDocument(conn)
	if err != nil {
		log.Fatalf("Failed to receive attestation document from enclave: %v", err)
	}
	log.Printf("Received attestation document (%d bytes).\n", len(attestationDoc))

	// 5. Parse the Attestation Document directly in Go
	pcrTable, err := parseAttestationDocumentGo(attestationDoc)
	if err != nil {
		log.Fatalf("Failed to parse attestation document with Go: %v", err)
	}

	log.Println("\n--- Attestation Document PCRs ---")
	for pcrIndex, pcrValue := range pcrTable {
		if pcrValue != "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" {
			log.Printf("PCR%s: %s\n", pcrIndex, pcrValue)
		}
	}

	// Example usage of GetInstanceID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	instanceID, err := GetInstanceID(ctx)
	if err != nil {
		log.Printf("Error getting instance ID (preferred method): %v", err)
	} else {
		log.Printf("Instance ID (from preferred method): %s\n", instanceID)
		log.Printf("SHA384 hash of the Instance ID: %s\n", CalculateSHA384(instanceID))
	}

	log.Println("Parent application finished.")
}

// buildEIF builds the enclave EIF using Docker and nitro-cli
func buildEIF() {
	log.Println("Building Docker image for enclave...")
	// Determine target architecture
	targetArch := "amd64"
	if targetArch == "" {
		log.Fatal("TARGETARCH environment variable not set. Please set it to 'amd64' or 'arm64' based on your EC2 instance type.")
	}

	dockerBuildCmd := exec.Command("docker", "build", "-t", "go-enclave-app", "--build-arg", fmt.Sprintf("TARGETARCH=%s", targetArch), "./enclave")
	dockerBuildCmd.Stdout = os.Stdout
	dockerBuildCmd.Stderr = os.Stderr
	if err := dockerBuildCmd.Run(); err != nil {
		log.Fatalf("Docker build failed: %v", err)
	}
	log.Println("Docker image built.")

	log.Println("Building EIF file...")
	nitroBuildCmd := exec.Command("sudo", "nitro-cli", "build-enclave", "--docker-uri", "go-enclave-app", "--output-file", enclaveEIFPath)
	nitroBuildCmd.Stdout = os.Stdout
	nitroBuildCmd.Stderr = os.Stderr
	if err := nitroBuildCmd.Run(); err != nil {
		log.Fatalf("nitro-cli build-enclave failed: %v", err)
	}
	log.Printf("EIF file created: %s\n", enclaveEIFPath)
}

// launchEnclave launches the Nitro Enclave and returns its ID
func launchEnclave(eifPath string, cid int) (string, error) {
	// Reverted to cpu-count 2 as it's required for AMD/Intel, memory 64MB for testing
	cmd := exec.Command("sudo", "nitro-cli", "run-enclave",
		"--cpu-count", "2",
		"--memory", "64", // Keep this low for now to get past launch
		"--enclave-cid", fmt.Sprintf("%d", cid),
		"--eif-path", eifPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error running nitro-cli run-enclave: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	jsonStart := strings.Index(outputStr, "{")
	if jsonStart == -1 {
		return "", fmt.Errorf("error: No JSON output found (missing '{') from nitro-cli run-enclave\nOutput: %s", outputStr)
	}
	jsonEnd := strings.LastIndex(outputStr, "}")
	if jsonEnd == -1 {
		return "", fmt.Errorf("error: No JSON output found (missing '}') from nitro-cli run-enclave\nOutput: %s", outputStr)
	}
	if jsonStart > jsonEnd {
		return "", fmt.Errorf("error: Malformed JSON output (start after end) from nitro-cli run-enclave\nOutput: %s", outputStr)
	}
	jsonBlock := outputStr[jsonStart : jsonEnd+1]

	var result struct {
		EnclaveID string `json:"EnclaveID"`
	}
	if err := json.Unmarshal([]byte(jsonBlock), &result); err != nil {
		return "", fmt.Errorf("failed to parse nitro-cli run-enclave output: %v\nOutput: %s\nExtracted JSON: %s", err, outputStr, jsonBlock)
	}
	return result.EnclaveID, nil
}

// terminateEnclave terminates a running Nitro Enclave
func terminateEnclave(enclaveID string) {
	log.Printf("Terminating enclave %s...\n", enclaveID)
	cmd := exec.Command("sudo", "nitro-cli", "terminate-enclave", "--enclave-id", enclaveID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error terminating enclave %s: %v\nOutput: %s\n", enclaveID, err, output)
	} else {
		log.Printf("Enclave %s terminated.\n", enclaveID)
	}
	// Clean up the EIF file
	if err := os.Remove(enclaveEIFPath); err != nil {
		log.Printf("Warning: Failed to remove EIF file %s: %v\n", enclaveEIFPath, err)
	}
}

// receiveAttestationDocument reads the attestation document from the vsock connection
func receiveAttestationDocument(conn io.Reader) ([]byte, error) { // Changed conn to io.Reader for broader compatibility
	// Read the 4-byte length prefix
	lenBytes := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBytes); err != nil {
		return nil, fmt.Errorf("failed to read attestation document length: %w", err)
	}
	docLen := binary.BigEndian.Uint32(lenBytes)

	log.Printf("Expecting attestation document of %d bytes...\n", docLen)

	// Read the actual attestation document bytes
	attestationDoc := make([]byte, docLen)
	if _, err := io.ReadFull(conn, attestationDoc); err != nil {
		return nil, fmt.Errorf("failed to read attestation document content: %w", err)
	}

	return attestationDoc, nil
}

// parseAttestationDocumentGo parses the raw CBOR attestation document.
// This function does NOT perform cryptographic signature verification,
// which is a critical step for production use cases.
func parseAttestationDocumentGo(doc []byte) (map[string]string, error) {
	var coseMessage []interface{}
	if err := cbor.Unmarshal(doc, &coseMessage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE message (outer CBOR): %w", err)
	}

	if len(coseMessage) < 4 {
		return nil, fmt.Errorf("malformed COSE message: expected at least 4 elements, got %d", len(coseMessage))
	}

	payload, ok := coseMessage[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("malformed COSE message: payload is not a byte array")
	}

	var attestationReport map[string]interface{}
	if err := cbor.Unmarshal(payload, &attestationReport); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation report (inner CBOR payload): %w", err)
	}

	pcrsRaw, ok := attestationReport["pcrs"].(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("pcrs field not found or not a map in attestation report")
	}

	pcrTable := make(map[string]string)
	for k, v := range pcrsRaw {
		// Corrected type assertions for CBOR unmarshaling
		var pcrIndex int // Declare as int, then convert from uint64
		indexUint64, indexOk := k.(uint64) // CBOR unmarshals integer keys as uint64
		if indexOk {
			pcrIndex = int(indexUint64) // Convert uint64 to int
		} else {
			// Fallback: if not uint64, try int (though less common for CBOR keys)
			indexInt, intOk := k.(int)
			if intOk {
				pcrIndex = indexInt
			} else {
				log.Printf("Warning: Unexpected PCR key format - type %T, value %v\n", k, k)
				continue // Skip this PCR if key format is unknown
			}
		}

		pcrValueBytes, valueOk := v.([]byte) // CBOR unmarshals byte array values as []byte
		if !valueOk {
			// Fallback: if not []byte, try []uint8 (which is the same underlying type)
			pcrValueUint8, uint8Ok := v.([]uint8)
			if uint8Ok {
				pcrValueBytes = pcrValueUint8 // Assign []uint8 to []byte
			} else {
				log.Printf("Warning: Unexpected PCR value format for key %v - type %T, value %v\n", k, v, v)
				continue // Skip this PCR if value format is unknown
			}
		}

		pcrTable[fmt.Sprintf("%d", pcrIndex)] = hex.EncodeToString(pcrValueBytes)
	}

	return pcrTable, nil
}

// GetInstanceID retrieves the EC2 instance ID using the Instance Identity Document.
// It is the recommended approach as it leverages IMDSv2 and provides a structured response.
// It takes a context for cancellation and timeouts.
func GetInstanceID(ctx context.Context) (string, error) {
	// Load the AWS SDK configuration.
	// This will automatically try to use the IMDS if no other credentials are found.
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to load SDK config: %w", err)
	}

	// Create an EC2 IMDS client.
	client := imds.NewFromConfig(cfg)

	// Attempt to get the instance identity document.
	doc, err := client.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get instance identity document: %w", err)
	}

	log.Printf("InstanceID: %s\n", doc.InstanceID)

	return doc.InstanceID, nil
}

func CalculateSHA384(input string) string {
	// Create a new SHA-384 hash object
	h := sha512.New384()

	nullBytes := make([]byte, 48) // Create a slice of 48 null bytes (defaults to 0)
	h.Write(nullBytes)      // Update the hash with the null bytes

	// Write the input string as bytes to the hash object
	h.Write([]byte(input))

	// Get the sum of the hash (a byte slice)
	hashSum := h.Sum(nil)

	// Encode the byte slice to a hexadecimal string for common representation
	return hex.EncodeToString(hashSum)
}
