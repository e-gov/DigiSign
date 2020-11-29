// Rakendus createkey genereerib ECDSA võtmepaari ja salvestab selle X.509 PEM failidesse
// privatekey.pem ja publickey.pem.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	// "crypto/sha256"
)

func main() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	publicKey := &privateKey.PublicKey

	encPriv, encPub := encode(privateKey, publicKey)

	// Salvesta võtmedpaar failidesse.
	err = ioutil.WriteFile("privatekey.pem", encPriv, 0644)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("publickey.pem", encPub, 0644)
	if err != nil {
		panic(err)
	}

}

// encode teisendab ECDSA võtmepaari X.509 PEM formaati. Tagastab []byte.
func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, []byte) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return pemEncoded, pemEncodedPub
}

// Märkmed
// How to store ECDSA private key in Go
// https://stackoverflow.com/questions/21322182/how-to-store-ecdsa-private-key-in-go
