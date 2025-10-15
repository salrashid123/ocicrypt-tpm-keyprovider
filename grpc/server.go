package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/containers/ocicrypt/keywrap/keyprovider"
	keyproviderpb "github.com/containers/ocicrypt/utils/keyprovider"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"

	"github.com/google/go-tpm/tpmutil"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	grpcport = flag.String("grpcport", ":50051", "grpcport")

	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

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
	fmt.Println("calling WrapKey")
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
		return nil, fmt.Errorf("error parsing Provider URL must be  provider:tpm:tpm://ek?mode=encrypt&pub=base64(ekpem)&pcrs=[pcrlist] got %s", tpmURI)
	}
	if u.Scheme != "tpm" {
		return nil, fmt.Errorf("error parsing Provider URL: unrecognized scheme got %s", u.Scheme)
	}

	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
	}

	if m["mode"] == nil {
		return nil, errors.New("error  mode=encrypt value must be set")
	}
	if m["mode"][0] != "encrypt" {
		return nil, errors.New("error  mode=encrypt value must be set")
	}

	if m["pub"] == nil {
		return nil, errors.New("error  /pub/ value must be set")
	}
	pubPEMData, err := base64.StdEncoding.DecodeString(m["pub"][0])
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
	}

	var pcrValues string
	if m["pcrs"] != nil {
		pcrValuesbytes, err := base64.StdEncoding.DecodeString(m["pcrs"][0])
		if err != nil {
			return nil, fmt.Errorf("error parsing pcr encoding: %v", err)
		}
		pcrValues = strings.TrimSuffix(string(pcrValuesbytes), "\n")
	}

	userAuth := ""
	if m["userAuth"] != nil {
		userAuthBytes, err := base64.StdEncoding.DecodeString(m["userAuth"][0])
		if err != nil {
			return nil, fmt.Errorf("error parsing pcr encoding: %v", err)
		}
		userAuth = strings.TrimSuffix(string(userAuthBytes), "\n")
	}

	isH2Parent := false
	if m["parentKeyType"] != nil {
		parentKeyType := m["parentKeyType"][0]
		if parentKeyType == "H2" {
			isH2Parent = true
		}
	}

	// block, _ := pem.Decode(pubPEMData)
	// pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	// if err != nil {
	// 	return nil, fmt.Errorf("Unable to load ekpub: %v", err)
	// }

	sessionKey := make([]byte, 32)
	_, err = rand.Read(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("unable to generate sessionkey: %v", err)
	}

	wrapper := tpmwrap.NewRemoteWrapper()
	if isH2Parent {
		_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			tpmwrap.TPM_PATH:              *tpmPath,
			tpmwrap.ENCRYPTING_PUBLIC_KEY: hex.EncodeToString(pubPEMData),
			tpmwrap.USER_AUTH:             userAuth,
			tpmwrap.PCR_VALUES:            pcrValues,
		}), tpmwrap.WithParentKeyH2(true))
	} else {
		_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			tpmwrap.TPM_PATH:              *tpmPath,
			tpmwrap.ENCRYPTING_PUBLIC_KEY: hex.EncodeToString(pubPEMData),
			tpmwrap.USER_AUTH:             userAuth,
			tpmwrap.PCR_VALUES:            pcrValues,
		}))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating wrapper %v\n", err)
		os.Exit(1)
	}

	//wrapper.SetConfig(ctx, tpmwrap.WithDebug(true))

	blobInfo, err := wrapper.Encrypt(ctx, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("error encrypting %v", err)
	}

	encodedBlob, err := protojson.Marshal(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("error marshalling bytes %v", err)
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, encodedBlob, "", "\t")
	if err != nil {
		return nil, fmt.Errorf("error marshalling json %v", err)
	}

	c, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("error creating Cipher error: %v", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM error: %v", err)
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
	fmt.Println("got unwrap")

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
		return nil, fmt.Errorf("error parsing Provider URL must be provider:tpm:tpm://ek?mode=decrypt got %s", tpmURI)
	}
	if u.Scheme != "tpm" {
		return nil, fmt.Errorf("error parsing Provider URL: unrecognized scheme got %s", u.Scheme)
	}
	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
	}
	if m["mode"] == nil {
		return nil, errors.New("error  mode must be set for decryption")
	}
	if m["mode"][0] != "decrypt" {
		return nil, errors.New("error  mode must set to decrypt")
	}

	// rwc, err := tpm2.OpenTPM(*tpmPath)
	// if err != nil {
	// 	return nil, fmt.Errorf("error: can't open TPM %s: %v", *tpmPath, err)
	// }
	// defer rwc.Close()

	if m["pub"] == nil {
		return nil, errors.New("error  /pub/ value must be set")
	}
	pubPEMData, err := base64.StdEncoding.DecodeString(m["pub"][0])
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
	}

	var pcrValues string
	if m["pcrs"] != nil {
		pcrValuesbytes, err := base64.StdEncoding.DecodeString(m["pcrs"][0])
		if err != nil {
			return nil, fmt.Errorf("error parsing pcr encoding: %v", err)
		}
		pcrValues = strings.TrimSuffix(string(pcrValuesbytes), "\n")
	}

	userAuth := ""
	if m["userAuth"] != nil {
		userAuthBytes, err := base64.StdEncoding.DecodeString(m["userAuth"][0])
		if err != nil {
			return nil, fmt.Errorf("error parsing pcr encoding: %v", err)
		}
		userAuth = strings.TrimSuffix(string(userAuthBytes), "\n")
	}

	isH2Parent := false
	if m["parentKeyType"] != nil {
		parentKeyType := m["parentKeyType"][0]
		if parentKeyType == "H2" {
			isH2Parent = true
		}
	}

	wrapper := tpmwrap.NewRemoteWrapper()
	if isH2Parent {
		_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			tpmwrap.TPM_PATH:              *tpmPath,
			tpmwrap.ENCRYPTING_PUBLIC_KEY: hex.EncodeToString(pubPEMData),
			tpmwrap.USER_AUTH:             userAuth,
			tpmwrap.PCR_VALUES:            pcrValues,
		}), tpmwrap.WithParentKeyH2(true))
	} else {
		_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			tpmwrap.TPM_PATH:              *tpmPath,
			tpmwrap.ENCRYPTING_PUBLIC_KEY: hex.EncodeToString(pubPEMData),
			tpmwrap.USER_AUTH:             userAuth,
			tpmwrap.PCR_VALUES:            pcrValues,
		}))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating wrapper %v\n", err)
		os.Exit(1)
	}

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(encryptedSessionKey, newBlobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error unmarshalling %v\n", err)
		os.Exit(1)
	}

	sessionKey, err := wrapper.Decrypt(ctx, newBlobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decrypting %v\n", err)
		os.Exit(1)
	}

	c, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create AES Cipher data: %v", err)
	}
	gcm, _ := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("unable to create GCM: %v", err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("uable to decrypt with GCM: %v", err)
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

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("Error: can't open TPM %s: %v", *tpmPath, err)
		os.Exit(1)
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
