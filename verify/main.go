// Rakendus verify loeb failist publickey.pem sisse ECDSA avaliku võtme, seejärel
// loeb sisse andmefaili data.txt ja allkirjafaili data.sign ning kontrollib allkirja.
// Kontrolli tulemuse väljastab konsoolile.
// Rakendus eeldab Go versiooni 1.13.
// Go versioonis 1.15 saab kasutada f-ni VerifyASN1, mis juba sisaldab ASN.1
// DER-formaadist dekodeerimist. Go versioonile 1.15 sobiv lühem lahendus on
// koodis ka teostatud, kuid välja kommenteeritud.
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
)

func main() {
	// Loe avalik võti failist sisse.
	pemEncoded, err := ioutil.ReadFile("publickey.pem")
	if err != nil {
		panic(err)
	}
	// Dekodeeri avalik võti.
	block, _ := pem.Decode(pemEncoded)
	// if err != nil {
	// 	panic(err)
	// }
	x509Encoded := block.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509Encoded)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	if err != nil {
		panic(err)
	}

	// Loe sisse andmefail.
	dat, err := ioutil.ReadFile("data.txt")
	if err != nil {
		panic(err)
	}

	// Arvuta andmefaili räsi.
	hash := sha256.Sum256([]byte(dat))

	// Loe sisse allkiri.
	sig, err := ioutil.ReadFile("data.sign")
	if err != nil {
		panic(err)
	}

	// Go 1.13. puhul on vajalik ASN.1 DER formaadist dekodeerimine
	// ecdsa esitab ECDSA allkirja kahte arvkomponenti.
	type ECDSASignature struct {
		R, S *big.Int
	}
	sigFromASN1 := &ECDSASignature{}
	_, err = asn1.Unmarshal(sig, sigFromASN1)
	if err != nil {
		panic(err)
	}

	// Kontrolli allkirja.
	// Go 1.15.
	// valid := ecdsa.VerifyASN1(publicKey, hash[:], sig)
	// Go 1.13.
	valid := ecdsa.Verify(publicKey, hash[:], sigFromASN1.R, sigFromASN1.S)
	fmt.Println("Allkiri kontrollitud:", valid)
}

// Märkmed
// How to store ECDSA private key in Go
// https://stackoverflow.com/questions/21322182/how-to-store-ecdsa-private-key-in-go

// Validating ECDSA Signatures in Golang
// https://thanethomson.com/2018/11/30/validating-ecdsa-signatures-golang/
