package blinding

import (
    "crypto"
    "crypto/rsa"
    "crypto/rand"
    _ "crypto/sha256"
    "github.com/cryptoballot/fdh"
    "github.com/cryptoballot/rsablind"
)

var Keysize = 2048
var Hashize = 1536
var ErrSlice = []byte("Error")
var err error

type Employee struct {
	key *rsa.PrivateKey
	signerskey *rsa.PublicKey
	message []byte
	unblinder []byte
}

func NewEmployee(signerskey *rsa.PublicKey) *Employee {
    key, err := rsa.GenerateKey(rand.Reader, Keysize)
	if err != nil {
		panic(err)
	}
	return &Employee{key, signerskey, nil, nil}
}

func (e * Employee) SetMessage(message []byte) {
	e.message = message
}


// employee salary blinding function
func (e * Employee) BlindSalary(message []byte) ([]byte, error) {
	e.message = message

    // We do a SHA256 full-domain-hash expanded to 1536 bits (3/4 the key size)
    hashed := fdh.Sum(crypto.SHA256, Hashize, message)

    // Blind the hashed message
	blind, unblinder, err := rsablind.Blind(e.signerskey, hashed)
	e.unblinder = unblinder
	return blind, err
}


// employee unblinds and checks sig
func (e * Employee) Unblind(blindSig []byte) ([]byte, error) {
    // Unblind the signature
	unBlindedSig := rsablind.Unblind(e.signerskey, blindSig, e.unblinder)

	// verify the sig
	err = e.VerifySallary(e.message, unBlindedSig, e.signerskey)
	if err != nil {
		return ErrSlice, err
	}
	return unBlindedSig, err
}

// For checking a publicly signed sallary
func (e * Employee) VerifySallary(message, sig []byte, signerspubkey *rsa.PublicKey) error {
	return VerifySallary(message, sig, e.signerskey)
}

func VerifySallary(message, sig []byte, signerspubkey *rsa.PublicKey) error {
    hashed := fdh.Sum(crypto.SHA256, Hashize, message)
	return rsablind.VerifyBlindSignature(signerspubkey, hashed, sig)
}

type Signer struct {
	key *rsa.PrivateKey
	employees *map[rsa.PublicKey]bool
}

func NewSigner() *Signer {
    key, err := rsa.GenerateKey(rand.Reader, Keysize)
	if err != nil {
		panic(err)
	}
	return &Signer{key, nil}
}

func (s *Signer) GetPub() rsa.PublicKey {
	return s.key.PublicKey
}

// Todo add auth
// third party signs salary
func (s *Signer) SignSalary(blinded []byte) (sig []byte, err error) {
	return rsablind.BlindSign(s.key, blinded)
}
