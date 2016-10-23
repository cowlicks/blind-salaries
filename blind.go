package blinding

import (
    "crypto"
    "crypto/rsa"
    _ "crypto/sha256"
    "github.com/cryptoballot/fdh"
    "github.com/cryptoballot/rsablind"
)

var Keysize = 2048
var Hashize = 1536
var ErrSlice = []byte("Error")
var err error

// employee salary blinding function
func BlindSalary(message []byte, signerspubkey *rsa.PublicKey) (blinded, unblinder []byte, err error) {
    // We do a SHA256 full-domain-hash expanded to 1536 bits (3/4 the key size)
    hashed := fdh.Sum(crypto.SHA256, Hashize, message)
    // Blind the hashed message
	return rsablind.Blind(signerspubkey, hashed)
}


// Todo add auth
// third party signs salary
func SignSalary(blinded []byte, signerskey *rsa.PrivateKey) (sig []byte, err error) {
	return rsablind.BlindSign(signerskey, blinded)
}


// employee unblinds and checks sig
func Unblind(message, blindSig, unblinder []byte, signerspubkey *rsa.PublicKey) ([]byte, error) {
    // Unblind the signature
	unBlindedSig := rsablind.Unblind(signerspubkey, blindSig, unblinder)

	// verify the sig
	err = VerifySallary(message, unBlindedSig, signerspubkey)
	if err != nil {
		return ErrSlice, err
	}
	return unBlindedSig, err
}


// For checking a publicly signed sallary
func VerifySallary(message, sig []byte, signerspubkey *rsa.PublicKey) error {
    hashed := fdh.Sum(crypto.SHA256, Hashize, message)
	return rsablind.VerifyBlindSignature(signerspubkey, hashed, sig)
}
