// Rakendus sign loeb failist privatekey.pem sisse ECDSA privaatvõtme, allkirjastab selle võtmega
//  faili data.txt ja salvestab allkirja faili data.sign.
// Rakendus on tehtud Go versioonile 1.13. Kasutab crypto/ecdsa f-ni Sign. Seetõttu on
// allkiri DER-formaadis salvestamine teha ilmutatult, paki asn1 abil.
// Go 1.15 saab kasutada f-ni SignASN1, mis juba sisaldab ASN.1 DER-formaati
// kodeerimist. Go versioonile 1.15 sobiv lühem lahendus on
// koodis ka teostatud, kuid välja kommenteeritud.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
)

func main() {
	// Loe privaatvõti failist sisse.
	pemEncoded, err := ioutil.ReadFile("privatekey.pem")
	if err != nil {
		panic(err)
	}
	// Dekodeeri privaatvõti.
	block, _ := pem.Decode(pemEncoded)
	// if err != nil {
	// 	panic(err)
	// }
	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		panic(err)
	}

	// Loe allkirjastatav andmefail sisse.
	dat3, err := ioutil.ReadFile("data.txt")
	if err != nil {
		panic(err)
	}

	// Allkirjasta andmefail.
	hash := sha256.Sum256([]byte(dat3))

	// SignASN1 on kasutatav alates Go 1.15.
	// sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	// if err != nil {
	// 	panic(err)
	// }

	// Go 1.13.
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		panic(err)
	}

	// Go 1.13.
	type ecdsa struct {
		R, S *big.Int
	}

	sequence := ecdsa{r, s}
	sig, _ := asn1.Marshal(sequence)

	// Väljasta allkiri konsoolile.
	fmt.Printf("signature: %x\n", sig)

	// Salvesta allkiri faili.
	err = ioutil.WriteFile("data.sign", sig, 0644)
	if err != nil {
		panic(err)
	}

}

// Märkmed
// Cannot use (type []byte) as type io.Reader
// https://stackoverflow.com/questions/44065935/cannot-use-type-byte-as-type-io-reader/44070040

// Validating ECDSA Signatures in Golang
// https://thanethomson.com/2018/11/30/validating-ecdsa-signatures-golang/

// Golang : Example for ECDSA(Elliptic Curve Digital Signature Algorithm) package functions
// https://www.socketloop.com/tutorials/golang-example-for-ecdsa-elliptic-curve-digital-signature-algorithm-functions

// How can I convert a DER ECDSA signature to ASN.1?
// https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1

// Go, DER and handling big integers
// https://stackoverflow.com/questions/8693513/go-der-and-handling-big-integers
