package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"

	"flag"

	"github.com/containers/ocicrypt/keywrap/keyprovider"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"

	"google.golang.org/protobuf/encoding/protojson"
)

const (
	tpmCryptName = "tpm"
)

var (
	tpmPath  = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	tpmURI   = flag.String("tpmURI", "", "TPM URI")
	debugLog = flag.String("debugLog", "", "Path to debuglog")
)

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

func main() {

	flag.Parse()

	if *debugLog != "" {
		file, err := os.OpenFile(*debugLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Printf("error opening log file: %v", err)
		}
		defer file.Close()
		log.SetOutput(file)
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	}

	var input keyprovider.KeyProviderKeyWrapProtocolInput
	err := json.NewDecoder(os.Stdin).Decode(&input)
	if err != nil {
		log.Printf("error decoding ocicrypt input %v\n", err)
		return
	}

	switch input.Operation {
	case keyprovider.OpKeyWrap:
		if *tpmURI != "" {
			if len(input.KeyWrapParams.Ec.Parameters) == 0 {
				input.KeyWrapParams.Ec.Parameters = make(map[string][][]byte)
			}
			input.KeyWrapParams.Ec.Parameters[tpmCryptName] = [][]byte{[]byte(*tpmURI)}
		}

		b, err := WrapKey(input)
		if err != nil {
			log.Fatalf("error wrapping key %v\n", err)
		}
		fmt.Printf("%s", b)
	case keyprovider.OpKeyUnwrap:
		// if the user specified it in command line, set that as the parameter value
		if *tpmURI != "" {
			if len(input.KeyUnwrapParams.Dc.Parameters) == 0 {
				input.KeyUnwrapParams.Dc.Parameters = make(map[string][][]byte)
			}
			input.KeyUnwrapParams.Dc.Parameters[tpmCryptName] = [][]byte{[]byte(*tpmURI)}
		}

		b, err := UnwrapKey(input)
		if err != nil {
			log.Fatalf("error unwrapping key %v\n", err)
		}
		fmt.Printf("%s", b)
	default:
		log.Fatalf("Operation %v not recognized", input.Operation)
	}
}

func WrapKey(keyP keyprovider.KeyProviderKeyWrapProtocolInput) ([]byte, error) {

	_, ok := keyP.KeyWrapParams.Ec.Parameters[tpmCryptName]
	if !ok {
		return nil, fmt.Errorf("provider must be formatted as provider:tpm:tpm://ek?&pub=base64(ekpem) not set, got %s", keyP.KeyWrapParams.Ec.Parameters[tpmCryptName])
	}

	if len(keyP.KeyWrapParams.Ec.Parameters[tpmCryptName]) == 0 {
		return nil, fmt.Errorf("provider must be formatted as provider:tpm:tpm://ek?&pub=base64(ekpem) got %s", keyP.KeyWrapParams.Ec.Parameters[tpmCryptName])
	}

	// get the first configuration
	//  todo://allow multiple config
	tpmURI := keyP.KeyWrapParams.Ec.Parameters[tpmCryptName][0]
	// parse the uri
	u, err := url.Parse(string(tpmURI))
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL must be  provider:tpm:tpm://ek?pt&pub=base64(ekpem) got %s", tpmURI)
	}
	if u.Scheme != tpmCryptName {
		return nil, fmt.Errorf("error parsing Provider URL: unrecognized scheme got %s", u.Scheme)
	}

	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
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
			return nil, fmt.Errorf("error parsing decoding userAuth: %v", err)
		}
		userAuth = strings.TrimSuffix(string(userAuthBytes), "\n")

		// remove the userAuth parameter from the tpmURI since this gets encoded
		// into the encrypted layer's metadata and we don't want the password to get seen
		q := u.Query()
		q.Del("userAuth")
		u.RawQuery = q.Encode()
		tpmURI = []byte(u.String())
	}

	isH2Parent := false
	if m["parentKeyType"] != nil {
		parentKeyType := m["parentKeyType"][0]
		if parentKeyType == "H2" {
			isH2Parent = true
		}
	}

	var aad []byte
	if m["aad"] != nil {
		aad = []byte(m["aad"][0])
		if *debugLog != "" {
			log.Printf("AAD: %s\n", m["aad"][0])
		}
	}

	// block, _ := pem.Decode(pubPEMData)
	// pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	// if err != nil {
	// 	return nil, fmt.Errorf("Unable to load ekpub: %v", err)
	// }

	sessionKey := make([]byte, 32)
	// if you wanted to go overboard https://github.com/salrashid123/tpmrand
	_, err = rand.Read(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("unable to generate sessionkey: %v", err)
	}

	ctx := context.Background()

	wrapper := tpmwrap.NewRemoteWrapper()

	_, err = wrapper.SetConfig(ctx,
		tpmwrap.WithEncryptingPublicKey(hex.EncodeToString(pubPEMData)),
		tpmwrap.WithPCRValues(pcrValues),
		tpmwrap.WithUserAuth(userAuth),
		tpmwrap.WithParentKeyH2(isH2Parent),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating wrapper %v", err)
	}

	blobInfo, err := wrapper.Encrypt(ctx, sessionKey, wrapping.WithAad(aad))
	if err != nil {
		return nil, fmt.Errorf("error encrypting %v", err)
	}

	encodedBlob, err := protojson.Marshal(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("error marshalling bytes %v", err)
	}

	if *debugLog != "" {
		var prettyJSON bytes.Buffer
		err = json.Indent(&prettyJSON, encodedBlob, "", "\t")
		if err != nil {
			return nil, fmt.Errorf("error marshalling json %v", err)
		}
		log.Printf("TPM wrapped sessionKey: %s\n", prettyJSON.String())
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

	// remove sensitive query parameters
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

	return json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyWrapResults: keyprovider.KeyWrapResults{
			Annotation: jsonString,
		},
	})

}

func UnwrapKey(keyP keyprovider.KeyProviderKeyWrapProtocolInput) ([]byte, error) {

	var err error

	apkt := annotationPacket{}
	err = json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
	if err != nil {
		return nil, err
	}

	// load up the keyURL if its in the packet
	tpmURI := apkt.KeyUrl
	encryptedSessionKey := apkt.SessionKey
	ciphertext := apkt.WrappedKey

	// now load it from the parameter; the paramater has the saved value the user specified in the commandline args
	//  the parameter value should take precedent over apkt.KeyUrl
	_, ok := keyP.KeyUnwrapParams.Dc.Parameters[tpmCryptName]
	if ok {
		if len(keyP.KeyUnwrapParams.Dc.Parameters[tpmCryptName]) == 0 && apkt.KeyUrl == "" {
			return nil, errors.New("decrypt Provider must be formatted as tpm://ek?pub=$H2PUB")
		}
		tpmURI = string(keyP.KeyUnwrapParams.Dc.Parameters[tpmCryptName][0])
	}

	if tpmURI == "" {
		return nil, errors.New("tpmURI cannot be nil")
	}

	// if tpmURI != apkt.KeyUrl {
	// 	return nil, fmt.Errorf("tpmURI parameter and keyURL in structure are different parameter [%s], keyURL [%s]", tpmURI, apkt.KeyUrl)
	// }

	// parse the uri
	u, err := url.Parse(string(tpmURI))
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL must be provider:tpm:tpm://ek? got %s", tpmURI)
	}
	if u.Scheme != tpmCryptName {
		return nil, fmt.Errorf("error parsing Provider URL: unrecognized scheme got %s", u.Scheme)
	}
	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
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

	var aad []byte
	if m["aad"] != nil {
		aad = []byte(m["aad"][0])
		if *debugLog != "" {
			log.Printf("AAD: %s\n", m["aad"][0])
		}
	}

	ctx := context.Background()
	wrapper := tpmwrap.NewRemoteWrapper()

	_, err = wrapper.SetConfig(ctx,
		tpmwrap.WithTPMPath(*tpmPath),
		tpmwrap.WithEncryptingPublicKey(hex.EncodeToString(pubPEMData)),
		tpmwrap.WithPCRValues(pcrValues),
		tpmwrap.WithUserAuth(userAuth),
		tpmwrap.WithParentKeyH2(isH2Parent),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating wrapper %v\n", err)
	}

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(encryptedSessionKey, newBlobInfo)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling %v\n", err)
	}

	sessionKey, err := wrapper.Decrypt(ctx, newBlobInfo, wrapping.WithAad(aad))
	if err != nil {
		return nil, fmt.Errorf("error decrypting %v\n", err)
	}

	c, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create AES Cipher data: %v", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("unable to create GCM: %v", err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("uable to decrypt with GCM: %v", err)
	}
	return json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyUnwrapResults: keyprovider.KeyUnwrapResults{OptsData: unwrappedKey},
	})
}
