## OCICrypt provider for Trusted Platform Modules (TPM)

Basic [OCICrypt KeyProvider](https://github.com/containers/ocicrypt/blob/main/docs/keyprovider.md) for TPM 

This repo includes a prebuilt and customizable keyprovider which can be used to encrypt OCI Containers using a given TPM's `Endorsement Public Key (EKPub)`.

[OCICrypt](https://github.com/containers/ocicrypt) includes specifications to encrypt an OCI Container image and within that, the keyprovider protocol allows wrapping of the actual key used to encrypt the layer to an external binary.

The binary in this question accepts a keyprovider request and inturn perform two further rounds of envelope encryption where the innermost key is bound to the TPM.

Basically, TPM wraps the symmetric key that is used to encrypt the layer itself.

This sample is based off of the [simple-oci-keyprovider](https://github.com/lumjjb/simple-ocicrypt-keyprovider.git) repo which demonstrates the protocol involved.

For more information, see 

- [Advancing container image security with encrypted container images](https://developer.ibm.com/articles/advancing-image-security-encrypted-container-images/)
- [Enabling advanced key usage and management in encrypted container images](https://developer.ibm.com/articles/enabling-advanced-key-usage-and-management-in-encrypted-container-images/)
- [Container Image Encryption & Decryption in the CoCo project](https://medium.com/kata-containers/confidential-containers-and-encrypted-container-images-fc4cdb332dec)
- [OCICrypt Container Image KMS Provider](https://github.com/salrashid123/ocicrypt-kms-keyprovider)

`ocicrypt` comes with default support for [PKCS11 support](https://github.com/containers/ocicrypt/blob/main/docs/pkcs11.md) already and you are free to apply a [TPM PKCS-11](https://github.com/tpm2-software/tpm2-pkcs11).  However, the specific path used by the ocicrypt utilizes an RSA Public key associated to a key derived from the `Storage Root Key (SRK)`.  Its similar to [this](https://github.com/salrashid123/tpm2/tree/master/encrypt_with_tpm_rsa) procedure.

While using the PKCS interface should work, the child RSA key should be attested and associated with the specific TPM first (i.,e you need to do remote attestation and the AK needs to certify the child key).  You also need to install the PKCS module on the target system...which is a bit of a pain.

This repo on the other hand uses the `Endorsement Publickey (EKPub)` directly to wrap an inner encryption key which is itself encrypts the oci metadata for the container image.

Basically, its a bit easier to use the EKPub because its usually something you can derive from a TPM Public x509 certificate (`EKCert`).

If a user has the EKPub key, you can encrypt some data such that *it can only* be decrypted on that TPM alone (nowhere else).

Furthermore, you can stipulate that the decryption has to be bound to certain PCR values.

The specific encryption/decryption and binding is described in [Sealing RSA and Symmetric keys with TPMs](https://github.com/salrashid123/gcp_tpm_sealed_keys/tree/main#sealed-symmetric-key)

Anyway, this repo shows how you can encrypt some data with an EKPub anywhere and have it only decrypted on a specific TPM (presumably after the remote system attested and verified)

In the end, the image itself is encrypted as shown below (in this case, just the last layer was encrypted; you can encrypt all of them if you want)


>> NOTE: this code is not supported by google.  caveat emptor

![images/manifest.png](images/manifest.png)

---

### QuickStart

#### Encrypt

To encrypt an image, acquire the PEM format of the ekPub file from the certificate and the PCR value list you want to bind to.

You can see an example of how to b64 encode the PEM file and the format to specify the PCRs.  Export them as `EKPUB` and `PCRLIST` variables.

from there, encrypt an image (eg `app:server` on the local docker daemon) and copy the encrypted image to a registry (in the example below, its my dockerhub image)

```bash
skopeo copy  --encrypt-layer=-1 \
  --encryption-key="provider:tpm:tpm://ek?mode=encrypt&pub=$EKPUB&pcrs=$PCRLIST" \
   docker-daemon:app:server docker://docker.io/salrashid123/ociencryptedapp:server
```

#### Decrypt

Decryption must be done on the same TPM where that ekPub exists.

First copy the `tpm_oci_crypt` binary onto the image and create an `ocicrypt.json` file that point to that


```json
{
  "key-providers": {
    "tpm": {
      "cmd": {
        "path": "/root/ocicrypt-tpm-keyprovider/plugin/tpm_oci_crypt",
        "args": ["--tpmPath=/dev/tpm0"]
      }
    }
  }
}
```

from there, specify the env vars that point to that config file

```bash
export OCICRYPT_KEYPROVIDER_CONFIG=/path/to/ocicrypt.json

skopeo copy --decryption-key="provider:tpm:tpm://ek?mode=decrypt" \
    docker://docker.io/salrashid123/ociencryptedapp:server docker://localhost:5000/app:decrypted
```

(ofcourse the command above won't work for you since you dont' have the key i used for that dockerhub image..but you get the  idea)

Just a note on using OCICrypt:  the image that is decrypted ...is decrypted so anyone who runs the command above can 'just copy' the image somewhere else, unarmored.  

Also note the PCR value binding:  if the pcr values change on the VM an _already_ downloaded/decrypted container will continue to run (since its already unarmored, etc)

---

### Setup

Before we jump in on using it live, lets demonstrate it running on a VM that has a TPM

#### Create VM

We're using a GCE image here:

```bash
gcloud compute instances create attestor  \
    --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
    --image-family=debian-10    --image-project=debian-cloud    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```

SSH to the VM and install the following

* [docker](https://docs.docker.com/engine/install/debian/)
* [skopeo 1.12.1](https://github.com/containers/skopeo/blob/main/install.md)
* optionally [cranev 0.14.0](https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md), docker
* `golang 1.19+`
* [tpm2_tools](https://tpm2-tools.readthedocs.io/en/latest/INSTALL/)

  See alternate install instruction [here](https://github.com/salrashid123/tpm2#installing-tpm2_tools-golang)
  We'll need tpm2_tools to read the pcr values and/or extract the EKPub


#### Run local registry

Cone the repo and run docker registry locally to test:

```bash
sudo su -
cd /root/
git clone https://github.com/salrashid123/ocicrypt-tpm-keyprovider
# all paths in this example is relative to the root
cd ocicrypt-tpm-keyprovider


cd example
docker run  -p 5000:5000 -v `pwd`/certs:/certs \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/localhost.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/localhost.key  docker.io/registry:2
```


#### Get EKPub Key and PCR values

In a new window, use `gcloud` to get the TPMs ekPub via the [get-shielded-identity](https://cloud.google.com/sdk/gcloud/reference/compute/instances/get-shielded-identity) API. 

If you're on your laptop, run the following and scp the `ekpub.pem` file to the tpm

```bash
gcloud compute instances get-shielded-identity attestor  \
  --zone=us-central1-a --format="value(encryptionKey.ekPub)" | awk '/^$/{n=n RS}; /./{printf "%s",n; n=""; print}' -  > /tmp/ekpub.pem

## for me the key was:
$ cat /tmp/ekpub.pem 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLLB37zQTi3KfKridPpY
tj9yKm0ci/QUGqrzBsVVqxqOsQUxocsaKMZPIO7VxJlJd8KHWMoGY6f1VOdNUFCN
ufg5WMqA/t6rXvjF4NtPTvR05dCV4JegBBDnOjF9NgmV67+NgAm3afq/Z1qvJ336
WUop2prbTWpseNtdlp2+4TOBSsNZgsum3CFr40qIsa2rb9xFDrqoMTVkgKGpJk+z
ta+pcxGXYFJfU9sb7F7cs3e+TzjucGFcpVEiFzVq6Mga8cmh32sufM/PuifVYSLi
BYV4s4c53gVq7v0Oda9LqaxT2A9EmKopcWUU8CEgbsBxhmVAhsnKwLDmJYKULkAk
uwIDAQAB
-----END PUBLIC KEY-----
```

If you have `tpm2_tools` installed on the remote vm, ssh in  and get its ekpub locally (we're doing this just to show you the keys are the same)

```bash
tpm2_createek -c ek.ctx -G rsa -u ek.pub -Q
tpm2_readpublic -c ek.ctx -o /tmp/ekpub.pem -f PEM -Q
cat /tmp/ekpub.pem

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLLB37zQTi3KfKridPpY
tj9yKm0ci/QUGqrzBsVVqxqOsQUxocsaKMZPIO7VxJlJd8KHWMoGY6f1VOdNUFCN
ufg5WMqA/t6rXvjF4NtPTvR05dCV4JegBBDnOjF9NgmV67+NgAm3afq/Z1qvJ336
WUop2prbTWpseNtdlp2+4TOBSsNZgsum3CFr40qIsa2rb9xFDrqoMTVkgKGpJk+z
ta+pcxGXYFJfU9sb7F7cs3e+TzjucGFcpVEiFzVq6Mga8cmh32sufM/PuifVYSLi
BYV4s4c53gVq7v0Oda9LqaxT2A9EmKopcWUU8CEgbsBxhmVAhsnKwLDmJYKULkAk
uwIDAQAB
-----END PUBLIC KEY-----
```

If a TPM has an Endorsement Key **Certificate**, you could cryptographically verify that and extract the public key.  
See [Extract ekcert from tpm and seal data against it](https://github.com/salrashid123/tpm2/tree/master/ek_cert_seal)

You can also list out the PCR values (you could also use golang as shown in [PCR Read and Extend](https://github.com/salrashid123/tpm2/blob/master/pcr_utils/README.md)):

```bash
tpm2_pcrread sha256:0
  sha256:
    0 : 0xD0C70A9310CD0B55767084333022CE53F42BEFBB69C059EE6C0A32766F160783
```

We're getting the PCR values here so that we can bind the decryption of the image to this PCR value(s)

Anyway, encode the key as base64 since we'll use this as the 'thing' to encrypt to (ofcourse your ekpub will certainly be different)

```bash

## base64 encode the following
export EKPUB=`openssl enc -base64 -A -in /tmp/ekpub.pem`
echo $EKPUB

# for the above its
# LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF5TExCMzd6UVRpM0tmS3JpZFBwWQp0ajl5S20wY2kvUVVHcXJ6QnNWVnF4cU9zUVV4b2NzYUtNWlBJTzdWeEpsSmQ4S0hXTW9HWTZmMVZPZE5VRkNOCnVmZzVXTXFBL3Q2clh2akY0TnRQVHZSMDVkQ1Y0SmVnQkJEbk9qRjlOZ21WNjcrTmdBbTNhZnEvWjFxdkozMzYKV1VvcDJwcmJUV3BzZU50ZGxwMis0VE9CU3NOWmdzdW0zQ0ZyNDBxSXNhMnJiOXhGRHJxb01UVmtnS0dwSmsregp0YStwY3hHWFlGSmZVOXNiN0Y3Y3MzZStUemp1Y0dGY3BWRWlGelZxNk1nYThjbWgzMnN1Zk0vUHVpZlZZU0xpCkJZVjRzNGM1M2dWcTd2ME9kYTlMcWF4VDJBOUVtS29wY1dVVThDRWdic0J4aG1WQWhzbkt3TERtSllLVUxrQWsKdXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==



```

For the PCR value, its encoded as comma-separated string of `PCR#=base64(lower(pcrvalue))`:

```bash
# 0=d0c70a9310cd0b55767084333022ce53f42befbb69c059ee6c0a32766f160783
## so for me it was encoded as
## export PCRLIST=`echo -n "0=d0c70a9310cd0b55767084333022ce53f42befbb69c059ee6c0a32766f160783" | openssl enc -base64 -A -in -`
export PCRLIST="MD1kMGM3MGE5MzEwY2QwYjU1NzY3MDg0MzMzMDIyY2U1M2Y0MmJlZmJiNjljMDU5ZWU2YzBhMzI3NjZmMTYwNzgz"
```

### Build Test application

Build a small test application which we will encrypt

```bash
cd example/
docker build -t app:server .

# inspect the image; note its not encrypted
skopeo inspect docker-daemon:app:server
```

### Encrypt

Either build the provider or use one from the `Releases` page in the repo (to build you need golang as well)

```bash
cd plugin/
go build -o tpm_oci_crypt
```

and set the path to the binary you created, eg:

```bash
vi example/ocicrypt.json
```

set

```json
{
  "key-providers": {
    "tpm": {
      "cmd": {
        "path": "/root/ocicrypt-tpm-keyprovider/plugin/tpm_oci_crypt",
        "args": ["--tpmPath=/dev/tpm0"]
      }
    }
  }
}
```

Now export the variables to bootstrap ocicrypt

```bash
cd example/
export OCICRYPT_KEYPROVIDER_CONFIG=/root/ocicrypt-tpm-keyprovider/example/ocicrypt.json
export SSL_CERT_FILE=certs/tls-ca-chain.pem

## make sure you have the variables set (remember, no padding)
echo $EKPUB
echo $PCRLIST

## now encrypt the last layer and copy to the docker daemon via skopeo:
skopeo copy  --encrypt-layer=-1 --encryption-key="provider:tpm:tpm://ek?mode=encrypt&pub=$EKPUB&pcrs=$PCRLIST"    docker-daemon:app:server docker://localhost:5000/app:encrypted

## if you inspect the node, you should see something like the following that shows encrypted layers
skopeo inspect docker://localhost:5000/app:encrypted
```


In my case, i pushed this image to dockerhub for you to see (you wont' be able to decrypt it...infact, i'll never be able to decrypt it since i shutdown the vm where the key resides)

```bash
skopeo copy  --preserve-digests  docker://localhost:5000/app:encrypted  docker://docker.io/salrashid123/ociencryptedapp:server
```


```json
$ crane manifest docker.io/salrashid123/ociencryptedapp:server | jq '.'

{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:952ad55c903eaceb39b6803a89954a506fa312c295e4e2c67efb1ee63d837238",
    "size": 2505
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:ef5c7eb8a1577c29c329af74dffacbedce1cd9b9938b42a09af0029ace8cc7e6",
      "size": 87117
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:80f00805faa81bccdbddf9458369d8dede6a30de1dced521f32a6237aeca64c2",
      "size": 20487
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:eb6702f4c235496acaa0a741db2a43a7d30f482004df4c02bdd384bd312e94b8",
      "size": 620188
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:c4629cdd872fe25c2febaf12f30590cbf351e0f77afd6079268a6b417c87788c",
      "size": 306
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:927ef23185e7d34c70bb0c9ac8bddf5665080cc821de3d16ac39cf4ee8cadc81",
      "size": 196
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:c23224575d87af713e0ff736a737712b034548de621b3d20b8d9360ecc6a8e70",
      "size": 115
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:b4aa04aa577f2b2f4b4a930e905d091b68b0719ec302b9abca710ffae50ebcaa",
      "size": 384
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:4e700e4525b70ee0923a4ee04eb0d4f53b0424933e4fbece3f801af6be4d8c32",
      "size": 350
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:b49267e860909c1e476d125b0b2057f9f17e8fa8484fa206e42466d91ee075e6",
      "size": 123525
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:305e3b8ad18c2bb9fb124bf7f350deb361200a4056541a4860c1b4a9a4c9daf0",
      "size": 5426220
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:84e64e6a79c8e6598eba2d9c01c4873b3310e7ce1de87253c170f6c8c898f962",
      "size": 1950667
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:86af40164b8f3c89c539bda9e01800269205ae775cc46be95772a6237904c621",
      "size": 936181
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:cc5fb384190effe65e3a772d1ce04f984c3c8dcb1ee2205cd27506b84f6b10fd",
      "size": 4234075
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
      "digest": "sha256:d276f6e01c3764c493788236bc04998bc107bd98347943d06959ca148a180fed",
      "size": 139,
      "annotations": {
        "org.opencontainers.image.enc.keys.provider.tpm": "eyJrZXlfdXJsIjoidHBtOi8vZWs/bW9kZT1lbmNyeXB0XHUwMDI2cHViPUxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVbEpRa2xxUVU1Q1oydHhhR3RwUnpsM01FSkJVVVZHUVVGUFEwRlJPRUZOU1VsQ1EyZExRMEZSUlVGNVRFeENNemQ2VVZScE0wdG1TM0pwWkZCd1dRcDBhamw1UzIwd1kya3ZVVlZIY1hKNlFuTldWbkY0Y1U5elVWVjRiMk56WVV0TldsQkpUemRXZUVwc1NtUTRTMGhYVFc5SFdUWm1NVlpQWkU1VlJrTk9DblZtWnpWWFRYRkJMM1EyY2xoMmFrWTBUblJRVkhaU01EVmtRMVkwU21WblFrSkViazlxUmpsT1oyMVdOamNyVG1kQmJUTmhabkV2V2pGeGRrb3pNellLVjFWdmNESndjbUpVVjNCelpVNTBaR3h3TWlzMFZFOUNVM05PV21kemRXMHpRMFp5TkRCeFNYTmhNbkppT1hoR1JISnhiMDFVVm10blMwZHdTbXNyZWdwMFlTdHdZM2hIV0ZsR1NtWlZPWE5pTjBZM1kzTXpaU3RVZW1wMVkwZEdZM0JXUldsR2VsWnhOazFuWVRoamJXZ3pNbk4xWmswdlVIVnBabFpaVTB4cENrSlpWalJ6TkdNMU0yZFdjVGQyTUU5a1lUbE1jV0Y0VkRKQk9VVnRTMjl3WTFkVlZUaERSV2RpYzBKNGFHMVdRV2h6Ymt0M1RFUnRTbGxMVlV4clFXc0tkWGRKUkVGUlFVSUtMUzB0TFMxRlRrUWdVRlZDVEVsRElFdEZXUzB0TFMwdENnPT1cdTAwMjZwY3JzPU1EMWtNR00zTUdFNU16RXdZMlF3WWpVMU56WTNNRGcwTXpNek1ESXlZMlUxTTJZME1tSmxabUppTmpsak1EVTVaV1UyWXpCaE16STNOalptTVRZd056Z3oiLCJzZXNzaW9uX2tleSI6IkNtd0FJTngyUWtSTHhtTW9mdzVCYjBpNGQxUXdjaGhmaDg4UHh1eWVSNTB0YU1XY0lvUlIrMCttQXVYY3lFeFFwdVNRbzhZK3FxVGZJS0lyU293UlI4cnBpdWY4WmRCMkJsMk1PenFVeHNoWUh2cUdyRENYUEpDNDlBTURnWUgwayt2OFFqMUY4L09IVnptS1F0QVNnQUs0S01rdlM1SUwzN3MxeU1SMlJLSDhEU1NDS1FtZ29EWldjMFA3a0tZNzc0c1hjUnZvQ2xORkVvZU44eUlXZnowSU1LT3NMVGZsdHR6SXpFOSs5ZDdzQ1Z5VW1FL1VrOCtSZ1JPVmdtSFZMZDJUUHFkc2xGNkgyemhQSVZ6dHJuQzNEMkZkUHJEZTVDNFF3Y3lYbytqdzAzVzRSS3UxOHZCZ3hVaHVGTE5SZXRkRXpjdVFFMlMyUVQ0Z29XWjdFNjd6NmxodHJlMndhUzI5ajFaZjYwKy9KcW9SOUtZRS9VZXk4ZlFFUVpQUWZTOUVQQkQxQ2NpMGpKek5oOVB6OUdPZmxGQ0orU1ZiMUtKa1hPT2Fub0ZDOHRGZCtrVnZSU1hDZEppTElFSjVPckoyakUxMmVRYUNXSkRpd0NEZXVOaUhhNmpGTXIvbTc2T05XRlpwbW1EekdrNEFDQUFMQUFBQWdBQWdBWll4YkROMDNvSnZTbmd2bXdEaER6UTQxSDhGWW9WNnBRQjdhQkJJa040QUVBQWdoZWFDUzA2K1U2cDU5c1M2Zmhnc3dsQW80QmI1V2lmRDJpOGpobTJxVnBjaUtBZ0xFaVFJQUJJZzBNY0treEROQzFWMmNJUXpNQ0xPVS9Rcjc3dHB3Rm51YkFveWRtOFdCNE09Iiwid3JhcHBlZF9rZXkiOiJLczlFUE1OK1BGSkFOd2t6ZjkrbXV3TDJ0cnM5QlMwTWZhZU1GMHBrbFlZR1BMeEhaSUxQYk11QXBJWnRoaGwyMmxDTTVQcnpnQTNhRzVoQXFKeWkvdGFwTkV1KzVyalFlWGZzTi9nek1KZWc1SEVKTFhEcEg5bDVYZzQ0Y2ZYQXg3clJVczYxUUpUL3dzUyt0N2s5eG5wYUljazgrZ0xpRUcvMjZ4T1RGRElqKzRXd1Q3emtSVlZQUk1ka0dvMy9Bdk9EYVJRTGVHZWJaL3lHT2ZaaTlyZVZISGhCd0hXTWltdURKQUdHRnRXZVV5Ukd6aGlRTE1mSlY2T0EyMmdZSUIrcHVqQ3FzaTNnMzkwa2NpaVZoRjNQMkJBc01Rc0FjSTE2L2JvPSIsIndyYXBfdHlwZSI6IkFFUyJ9",
        "org.opencontainers.image.enc.pubopts": "eyJjaXBoZXIiOiJBRVNfMjU2X0NUUl9ITUFDX1NIQTI1NiIsImhtYWMiOiIrRDJqeTcxOVZFS2pFY0FkWFEra0UxYUtQZjJUYUhIU1IxajJBK0dlRzY0PSIsImNpcGhlcm9wdGlvbnMiOnt9fQ=="
      }
    }
  ]
}
```

if you decode the JWT, you'll see

```json
{
  "key_url": "tpm://ek?mode=encrypt&pub=LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF5TExCMzd6UVRpM0tmS3JpZFBwWQp0ajl5S20wY2kvUVVHcXJ6QnNWVnF4cU9zUVV4b2NzYUtNWlBJTzdWeEpsSmQ4S0hXTW9HWTZmMVZPZE5VRkNOCnVmZzVXTXFBL3Q2clh2akY0TnRQVHZSMDVkQ1Y0SmVnQkJEbk9qRjlOZ21WNjcrTmdBbTNhZnEvWjFxdkozMzYKV1VvcDJwcmJUV3BzZU50ZGxwMis0VE9CU3NOWmdzdW0zQ0ZyNDBxSXNhMnJiOXhGRHJxb01UVmtnS0dwSmsregp0YStwY3hHWFlGSmZVOXNiN0Y3Y3MzZStUemp1Y0dGY3BWRWlGelZxNk1nYThjbWgzMnN1Zk0vUHVpZlZZU0xpCkJZVjRzNGM1M2dWcTd2ME9kYTlMcWF4VDJBOUVtS29wY1dVVThDRWdic0J4aG1WQWhzbkt3TERtSllLVUxrQWsKdXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==&pcrs=MD1kMGM3MGE5MzEwY2QwYjU1NzY3MDg0MzMzMDIyY2U1M2Y0MmJlZmJiNjljMDU5ZWU2YzBhMzI3NjZmMTYwNzgz",
  "session_key": "CmwAINx2QkRLxmMofw5Bb0i4d1Qwchhfh88PxuyeR50taMWcIoRR+0+mAuXcyExQpuSQo8Y+qqTfIKIrSowRR8rpiuf8ZdB2Bl2MOzqUxshYHvqGrDCXPJC49AMDgYH0k+v8Qj1F8/OHVzmKQtASgAK4KMkvS5IL37s1yMR2RKH8DSSCKQmgoDZWc0P7kKY774sXcRvoClNFEoeN8yIWfz0IMKOsLTflttzIzE9+9d7sCVyUmE/Uk8+RgROVgmHVLd2TPqdslF6H2zhPIVztrnC3D2FdPrDe5C4QwcyXo+jw03W4RKu18vBgxUhuFLNRetdEzcuQE2S2QT4goWZ7E67z6lhtre2waS29j1Zf60+/JqoR9KYE/Uey8fQEQZPQfS9EPBD1Cci0jJzNh9Pz9GOflFCJ+SVb1KJkXOOanoFC8tFd+kVvRSXCdJiLIEJ5OrJ2jE12eQaCWJDiwCDeuNiHa6jFMr/m76ONWFZpmmDzGk4ACAALAAAAgAAgAZYxbDN03oJvSngvmwDhDzQ41H8FYoV6pQB7aBBIkN4AEAAgheaCS06+U6p59sS6fhgswlAo4Bb5WifD2i8jhm2qVpciKAgLEiQIABIg0McKkxDNC1V2cIQzMCLOU/Qr77tpwFnubAoydm8WB4M=",
  "wrapped_key": "Ks9EPMN+PFJANwkzf9+muwL2trs9BS0MfaeMF0pklYYGPLxHZILPbMuApIZthhl22lCM5PrzgA3aG5hAqJyi/tapNEu+5rjQeXfsN/gzMJeg5HEJLXDpH9l5Xg44cfXAx7rRUs61QJT/wsS+t7k9xnpaIck8+gLiEG/26xOTFDIj+4WwT7zkRVVPRMdkGo3/AvODaRQLeGebZ/yGOfZi9reVHHhBwHWMimuDJAGGFtWeUyRGzhiQLMfJV6OA22gYIB+pujCqsi3g390kciiVhF3P2BAsMQsAcI16/bo=",
  "wrap_type": "AES"
}
```

### Decrypt

First try to run the image:

```bash
$ docker run localhost:5000/app:encrypted

Unable to find image 'localhost:5000/app:encrypted' locally
encrypted: Pulling from app
ef5c7eb8a157: Already exists 
80f00805faa8: Already exists 
eb6702f4c235: Already exists 
c4629cdd872f: Already exists 
927ef23185e7: Already exists 
c23224575d87: Already exists 
b4aa04aa577f: Already exists 
4e700e4525b7: Already exists 
b49267e86090: Already exists 
305e3b8ad18c: Already exists 
84e64e6a79c8: Already exists 
86af40164b8f: Already exists 
4d04d94ae206: Already exists 
407097943978: Extracting [==================================================>]     139B/139B
docker: failed to register layer: unexpected EOF.

```

this wont' work because you dont have the key so copty the encrypted image over

```bash
skopeo copy --decryption-key="provider:tpm:tpm://ek?mode=decrypt"  docker://localhost:5000/app:encrypted  docker://localhost:5000/app:decrypted
```

Now running it works

```bash
$ docker run localhost:5000/app:decrypted

Unable to find image 'localhost:5000/app:decrypted' locally
decrypted: Pulling from app
ef5c7eb8a157: Already exists 
d0725b4f7d72: Pull complete 
Digest: sha256:accd86b929da7a547a384fa74e37a150a50df2ed2567baa9f1bf298f2093aec7
Status: Downloaded newer image for localhost:5000/app:decrypted
config {
    "foo": "bar",
    "bar": "bar"
}
Starting Server..
```

You can inspect the values in the registry to confirm encrypted status or not by running

```bash
skopeo inspect --tls-verify  docker://localhost:5000/app:encrypted
skopeo inspect --tls-verify  docker://localhost:5000/app:decrypted

crane manifest localhost:5000/app:encrypted | jq '.'
crane manifest  localhost:5000/app:decrypted | jq '.'
```

## Invalid PCR value

Finally, lets encrypt the image with a bad PCR value binding.  

So lets make one up:

```bash
# 7=643c832d74ca5a76c27d7d88987f332ed2eb7222e1333e6abac8fd55635b59b0247d786bdedee42d7f7b04180b67c9ec
## would be
export PCRLIST="Nz02NDNjODMyZDc0Y2E1YTc2YzI3ZDdkODg5ODdmMzMyZWQyZWI3MjIyZTEzMzNlNmFiYWM4ZmQ1NTYzNWI1OWIwMjQ3ZDc4NmJkZWRlZTQyZDdmN2IwNDE4MGI2N2M5ZWM="

# and push the aseline image to app:badimage
skopeo copy  --encrypt-layer=-1 --encryption-key="provider:tpm:tpm://ek?mode=encrypt&pub=$EKPUB&pcrs=$PCRLIST"    docker-daemon:app:server docker://localhost:5000/app:badencrypted

## now try to pull and run the image
skopeo copy --decryption-key="provider:tpm:tpm://ek?mode=decrypt"  docker://localhost:5000/app:badencrypted docker://localhost:5000/app:stillbad

no suitable key found for decrypting layer key:
- Error while running command: /root/ocicrypt-tpm-keyprovider/plugin/tpm_oci_crypt. stderr: 2023/06/17 07:51:12 Error unwrapping key Unable to Import sealed data: unseal failed: session 1, error code 0x1d : a policy check failed
: exit status 1
```

