package main

import (
	_ "embed"
	"errors"
	cliFlag "flag"
	"math/rand"
	"strconv"

	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/gorilla/mux"
)

const SerializedScalarSize = 32
const ScalarsPerBlob = 4096
const ProofSize = 48

var adminSeed int64
var adminBlob *gokzg4844.Blob

var flag string

//go:embed trusted_setup.json
var kzgSetupStr string
var kzgContext *gokzg4844.Context

var portRef = cliFlag.Int("port", 13337, "listen")

func main() {
	cliFlag.Parse()
	if err := New4844Context(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Loaded trusted setup")

	flag = os.Getenv("FLAG")
	if flag == "" {
		log.Fatal(errors.New("flag not set"))
	}

	var err error
	rawAdminSeed := os.Getenv("ADMIN_SEED")
	adminSeed, err = strconv.ParseInt(rawAdminSeed, 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Init admin seed")

	if err := NewAdminBlob(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Init admin blob")

	fmt.Printf("Starting server at port %d\n", *portRef)

	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/alive", handleAlive).Methods("GET")
	router.HandleFunc("/random/blob", handleRandBlob).Methods("GET")
	router.HandleFunc("/admin/eval", handleAdminEval).Methods("POST")
	router.HandleFunc("/admin/verify", handleAdminVerify).Methods("POST")
	router.HandleFunc("/admin/flag", handleAdminFlag).Methods("POST")

	addr := fmt.Sprintf(":%d", *portRef)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatal(err)
	}
}

func New4844Context() error {
	parsedSetup := gokzg4844.JSONTrustedSetup{}
	if err := json.Unmarshal([]byte(kzgSetupStr), &parsedSetup); err != nil {
		return err
	}
	var err error
	if kzgContext, err = gokzg4844.NewContext4096(&parsedSetup); err != nil {
		return err
	}
	return nil
}

func GetRandFieldElement(seed int64) ([32]byte, error) {
	rand.Seed(seed)

	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to get random field element: %w", err)
	}

	var r fr.Element
	r.SetBytes(bytes)

	return gokzg4844.SerializeScalar(r), nil
}

func GetRandBlob(seed int64) (*gokzg4844.Blob, error) {
	var blob gokzg4844.Blob
	bytesPerBlob := gokzg4844.ScalarsPerBlob * gokzg4844.SerializedScalarSize
	for i := 0; i < bytesPerBlob; i += gokzg4844.SerializedScalarSize {
		fieldElementBytes, err := GetRandFieldElement(seed + int64(i))
		if err != nil {
			return nil, err
		}
		copy(blob[i:i+gokzg4844.SerializedScalarSize], fieldElementBytes[:])
	}
	return &blob, nil
}

func EncodeBlob(blob *gokzg4844.Blob) ([]byte, error) {
	result := []byte(base64.StdEncoding.EncodeToString((*blob)[:]))
	return result, nil
}

func NewAdminBlob() error {
	var err error
	adminBlob, err = GetRandBlob(adminSeed)
	if err != nil {
		return err
	}
	return nil
}

func handleAlive(rw http.ResponseWriter, req *http.Request) {
	if adminBlob == nil || kzgContext == nil {
		rw.WriteHeader(http.StatusInternalServerError)
		http.Error(rw, "Something went wrong. Ping admin!", http.StatusBadRequest)
		return
	}
	rw.Write([]byte("https://www.youtube.com/watch?v=Y6ljFaKRTrI"))
}

type ProofRequest struct {
	Blob  string `json:"blob,omitempty"`
	Input string `json:"input"`
}

func handleAdminEval(rw http.ResponseWriter, req *http.Request) {
	var request ProofRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		http.Error(rw, "Failed to decode JSON request", http.StatusBadRequest)
		return
	}
	inputPoint, err := decodeInputPoint(request.Input)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	_, claimedValue, err := kzgContext.ComputeKZGProof(*adminBlob, inputPoint, 4)
	if err != nil {
		http.Error(rw, "KZG proof computation failure", http.StatusBadRequest)
		return
	}
	rw.WriteHeader(http.StatusOK)
	json.NewEncoder(rw).Encode(
		map[string][]byte{"claimedValue": claimedValue[:]},
	)
}

type VerifyRequest struct {
	Input        string `json:"input"`
	ClaimedValue string `json:"claimedValue"`
	Commitment   string `json:"commitment,omitempty"`
	Proof        string `json:"proof"`
}

func handleAdminVerify(rw http.ResponseWriter, req *http.Request) {
	var request VerifyRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		http.Error(rw, "Failed to decode JSON request", http.StatusBadRequest)
		return
	}

	commitment, err := kzgContext.BlobToKZGCommitment(*adminBlob, 4)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		http.Error(rw, "Something went wrong. Ping admin!", http.StatusBadRequest)
		return
	}

	inputPoint, err := decodeInputPoint(request.Input)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	claimedValue, err := decodeClaimedValue(request.ClaimedValue)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	proof, err := decodeProof(request.Proof)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	if err := kzgContext.VerifyKZGProof(commitment, inputPoint, claimedValue, proof); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Invalid"))
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Valid"))
}

func handleAdminFlag(rw http.ResponseWriter, req *http.Request) {
	var request VerifyRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		http.Error(rw, "Failed to decode JSON request", http.StatusBadRequest)
		return
	}
	commitment, err := kzgContext.BlobToKZGCommitment(*adminBlob, 4)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		http.Error(rw, "Something went wrong. Ping admin!", http.StatusBadRequest)
		return
	}

	inputPoint, err := decodeInputPoint(request.Input)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	claimedValue, err := decodeClaimedValue(request.ClaimedValue)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	proof, err := decodeProof(request.Proof)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	// compute myself
	_, targetClaimedValue, err := kzgContext.ComputeKZGProof(*adminBlob, inputPoint, 4)
	if err != nil {
		http.Error(rw, "KZG proof computation failure", http.StatusBadRequest)
		return
	}
	// must be different
	if targetClaimedValue == claimedValue {
		http.Error(rw, "https://www.youtube.com/watch?v=dQw4w9WgXcQ", http.StatusBadRequest)
		return
	}
	if err := kzgContext.VerifyKZGProof(commitment, inputPoint, claimedValue, proof); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Invalid"))
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(flag))
}

func handleRandBlob(rw http.ResponseWriter, req *http.Request) {
	seed := time.Now().Unix()
	blob, err := GetRandBlob(seed)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	result, err := EncodeBlob(blob)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write(result)
}

func decodeBlob(input string) (*gokzg4844.Blob, error) {
	rawBlob, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, errors.New("failed to decode base64")
	}
	if len(rawBlob) != ScalarsPerBlob*SerializedScalarSize {
		return nil, errors.New("input length mismatch")
	}
	var blob gokzg4844.Blob
	copy(blob[:], rawBlob)
	return &blob, nil
}

func decodeInputPoint(input string) ([SerializedScalarSize]byte, error) {
	if len(input) != 64 {
		return [SerializedScalarSize]byte{}, errors.New("input should be a 32-byte hex string")
	}
	rawInput, err := hex.DecodeString(input)
	if err != nil {
		return [SerializedScalarSize]byte{}, errors.New("invalid hex string")
	}
	var inputPoint [SerializedScalarSize]byte
	copy(inputPoint[:], rawInput)
	return inputPoint, nil
}

func decodeClaimedValue(input string) (gokzg4844.Scalar, error) {
	rawClaimedValue, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return gokzg4844.Scalar{}, errors.New("failed to decode base64")
	}
	if len(rawClaimedValue) != SerializedScalarSize {
		return gokzg4844.Scalar{}, errors.New("input length mismatch")
	}
	var claimedValue gokzg4844.Scalar
	copy(claimedValue[:], rawClaimedValue)
	return claimedValue, nil
}

func decodeProof(input string) (gokzg4844.KZGProof, error) {
	rawProof, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return gokzg4844.KZGProof{}, errors.New("failed to decode base64")
	}
	if len(rawProof) != ProofSize {
		return gokzg4844.KZGProof{}, errors.New("input length mismatch")
	}
	var proof gokzg4844.KZGProof
	copy(proof[:], rawProof)
	return proof, nil
}
