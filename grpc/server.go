package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/containers/ocicrypt/keywrap/keyprovider"
	keyproviderpb "github.com/containers/ocicrypt/utils/keyprovider"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	tpmserver "github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

var (
	grpcport = flag.String("grpcport", ":50051", "grpcport")

	tpmPath        = flag.String("tpmPath", "", "Path to TPM")
	flushTPMHandle = flag.String("flushTPMHandle", "all", "Flush TPM handles")

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
		"none":      {},
	}
)

const (
	tpmCryptName = "grpc-keyprovider"
)

type server struct {
	keyproviderpb.UnimplementedKeyProviderServiceServer
}

// note the SessionKey is an AESGCM key that is generated entirely within the code
//  the seession key is what encrypts the ocicrypt request and the sessionKey is itself
//  encrypted by the TPM.  We're doing this because the size of the data that the TPM can
//  encrypt with the EKPub is limited.  so we do two layers of wrapping

type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	SessionKey []byte `json:"session_key"`
	WrappedKey []byte `json:"wrapped_key"`
	WrapType   string `json:"wrap_type"`
}

func (*server) WrapKey(ctx context.Context, request *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	log.Println("got WrapKey")
	var keyP keyprovider.KeyProviderKeyWrapProtocolInput
	err := json.Unmarshal(request.KeyProviderKeyWrapProtocolInput, &keyP)
	if err != nil {
		return nil, err
	}

	_, ok := keyP.KeyWrapParams.Ec.Parameters[tpmCryptName]
	if !ok {
		return nil, fmt.Errorf("Provider must be formatted as provider:grpc-keyprovider:tpm://ek?mode=encrypt&pub=base64(ekpem)&pcrs=[pcrlist] not set, got %s", keyP.KeyWrapParams.Ec.Parameters[tpmCryptName])
	}

	if len(keyP.KeyWrapParams.Ec.Parameters[tpmCryptName]) == 0 {
		return nil, fmt.Errorf("Provider must be formatted as provider:grpc-keyprovider:tpm://ek?mode=encrypt&pub=base64(ekpem)&pcrs=[pcrlist] got %s", keyP.KeyWrapParams.Ec.Parameters[tpmCryptName])
	}

	// get the first configuration
	//  todo://allow multiple config
	tpmURI := keyP.KeyWrapParams.Ec.Parameters[tpmCryptName][0]
	// parse the uri
	u, err := url.Parse(string(tpmURI))
	if err != nil {
		return nil, fmt.Errorf("Error parsing Provider URL must be  provider:tpm:tpm://ek?mode=encrypt&pub=base64(ekpem)&pcrs=[pcrlist] got %s", tpmURI)
	}

	if u.Scheme != "tpm" {
		return nil, fmt.Errorf("Error parsing Provider Scheme must be tpm:// %s", u.Scheme)
	}
	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("Error parsing Provider URL: %v", err)
	}

	if m["mode"] == nil {
		return nil, errors.New("Error  mode=encrypt value must be set")
	}
	if m["mode"][0] != "encrypt" {
		return nil, errors.New("Error  mode=encrypt value must be set")
	}

	if m["pub"] == nil {
		return nil, errors.New("Error  /pub/ value must be set")
	}
	pubPEMData, err := base64.StdEncoding.DecodeString(m["pub"][0])
	if err != nil {
		return nil, fmt.Errorf("Error parsing Provider URL: %v", err)
	}

	pcrMap := map[uint32][]byte{}
	if m["pcrs"] != nil {
		pcrdecoded, err := base64.StdEncoding.DecodeString(m["pcrs"][0])
		if err != nil {
			return nil, fmt.Errorf("Error decoding pcrs: %v\n", err)
		}
		entries := strings.Split(string(pcrdecoded), ",")
		pcrMap = make(map[uint32][]byte)
		for _, e := range entries {
			parts := strings.Split(e, "=")
			u, err := strconv.ParseUint(parts[0], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("Error parsing uint64->32: %v\n", err)
			}

			hv, err := hex.DecodeString(parts[1])
			if err != nil {
				return nil, fmt.Errorf("Error decoding hex string: %v\n", err)
			}
			pcrMap[uint32(u)] = hv
		}
	}
	var pcrs *pb.PCRs
	if len(pcrMap) == 0 {
		pcrs = nil
	} else {
		pcrs = &pb.PCRs{Hash: pb.HashAlgo_SHA256, Pcrs: pcrMap}
	}

	block, _ := pem.Decode(pubPEMData)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to load ekpub: %v", err)
	}

	sessionKey := make([]byte, 32)
	_, err = rand.Read(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate sessionkey: %v", err)
	}

	blob, err := tpmserver.CreateImportBlob(pub, sessionKey, pcrs)
	if err != nil {
		return nil, fmt.Errorf("Unable to CreateImportBlob : %v", err)
	}
	encodedBlob, err := proto.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("marshalling error: %v", err)
	}

	c, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("Error creating Cipher error: %v", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("Error creating GCM error: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	wrappedKey := gcm.Seal(nonce, nonce, keyP.KeyWrapParams.OptsData, nil)

	jsonString, err := json.Marshal(annotationPacket{
		KeyUrl:     string(tpmURI),
		SessionKey: encodedBlob,
		WrappedKey: wrappedKey,
		WrapType:   "AES",
	})
	if err != nil {
		return nil, fmt.Errorf("error encoding annotation Packet: %v", err)
	}

	protocolOuputSerialized, _ := json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyWrapResults: keyprovider.KeyWrapResults{Annotation: jsonString},
	})

	return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolOuputSerialized,
	}, nil
}

func (*server) UnWrapKey(ctx context.Context, request *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	log.Println("got UnWrapKey")
	var keyP keyprovider.KeyProviderKeyWrapProtocolInput
	err := json.Unmarshal(request.KeyProviderKeyWrapProtocolInput, &keyP)
	if err != nil {
		return nil, err
	}

	apkt := annotationPacket{}
	err = json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
	if err != nil {
		return nil, err
	}

	encryptedSessionKey := apkt.SessionKey
	ciphertext := apkt.WrappedKey

	_, ok := keyP.KeyUnwrapParams.Dc.Parameters[tpmCryptName]
	if !ok {
		return nil, fmt.Errorf("Provider must be formatted as provider:grpc-keyprovider:tpm://ek?mode=decrypt, got %s", keyP.KeyWrapParams.Ec.Parameters[tpmCryptName])
	}

	if len(keyP.KeyUnwrapParams.Dc.Parameters[tpmCryptName]) == 0 {
		return nil, fmt.Errorf("Provider must be formatted as provider:grpc-keyprovider:tpm://ek?mode=decrypt got %s", keyP.KeyWrapParams.Ec.Parameters[tpmCryptName])
	}

	// get the first configuration
	//  todo://allow multiple config
	tpmURI := keyP.KeyUnwrapParams.Dc.Parameters[tpmCryptName][0]
	// parse the uri
	u, err := url.Parse(string(tpmURI))
	if err != nil {
		return nil, fmt.Errorf("Error parsing Provider URL must be  provider:tpm:tpm://ek?mode=encrypt&pub=base64(ekpem)&pcrs=[pcrlist] got %s", tpmURI)
	}

	if u.Scheme != "tpm" {
		return nil, fmt.Errorf("Error parsing Provider Scheme must be tpm:// %s", u.Scheme)
	}
	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("Error parsing Provider URL: %v", err)
	}

	if m["mode"] == nil {
		return nil, errors.New("Error  mode must be set for decryption")
	}
	if m["mode"][0] != "decrypt" {
		return nil, errors.New("Error  mode must set to decrypt")
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return nil, fmt.Errorf("Error: can't open TPM %s: %v", *tpmPath, err)
	}
	defer rwc.Close()
	totalHandles := 0
	for _, handleType := range handleNames[*flushTPMHandle] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			return nil, fmt.Errorf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				return nil, fmt.Errorf("flushing handle 0x%x: %v", handle, err)
			}
			fmt.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		return nil, fmt.Errorf("Unable to load EK from TPM: %v", err)
	}

	blob := &pb.ImportBlob{}
	err = proto.Unmarshal(encryptedSessionKey, blob)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling error:%v ", err)
	}
	sessionKey, err := ek.Import(blob)
	if err != nil {
		return nil, fmt.Errorf("Unable to Import sealed data: %v", err)
	}

	c, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("Unable to create AES Cipher data: %v", err)
	}
	gcm, _ := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("Unable to create GCM: %v", err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to decrypt with GCM: %v", err)
	}

	protocolOuputSerialized, _ := json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyUnwrapResults: keyprovider.KeyUnwrapResults{OptsData: unwrappedKey},
	})
	return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolOuputSerialized,
	}, nil
}

func main() {

	flag.Parse()

	var err error

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("Error: can't open TPM %s: %v", *tpmPath, err)
		os.Exit(1)
	}

	totalHandles := 0
	for _, handleType := range handleNames[*flushTPMHandle] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			fmt.Printf("Error: deleting handles %s: %v", *tpmPath, err)
			os.Exit(1)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				fmt.Printf("flushing handle 0x%x: %v", handle, err)
				os.Exit(1)
			}
			totalHandles++
		}
	}
	err = rwc.Close()
	if err != nil {
		log.Fatalf("error closing tpm: %v", err)
	}

	log.Println("Starting server")
	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}
	sopts = append(sopts)

	s := grpc.NewServer(sopts...)
	keyproviderpb.RegisterKeyProviderServiceServer(s, &server{})

	log.Printf("Starting gRPC Server at %s", *grpcport)
	s.Serve(lis)

}
