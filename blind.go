package blinding

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"github.com/cryptoballot/fdh"
	"github.com/cryptoballot/rsablind"
)

var Keysize = 2048
var Hashize = 1536
var ErrSlice = []byte("Error")
var err error

// Other functions
func VerifySallary(message, sig []byte, signerspubkey *rsa.PublicKey) error {
	hashed := fdh.Sum(crypto.SHA256, Hashize, message)
	return rsablind.VerifyBlindSignature(signerspubkey, hashed, sig)
}

func SignPSS(message []byte, privkey *rsa.PrivateKey) ([]byte, error) {
	rng := rand.Reader
	hashed := sha256.Sum256(message)
	return rsa.SignPSS(rng, privkey, crypto.SHA256, hashed[:], nil)
}

func VerifyPSS(message, sig []byte, pubkey *rsa.PublicKey) error {
	hashed := sha256.Sum256(message)
	err = rsa.VerifyPSS(pubkey, crypto.SHA256, hashed[:], sig, nil)
	return err
}

/*********************
	   Employee
**********************/
type Employee struct {
	key        *rsa.PrivateKey
	signerskey *rsa.PublicKey
	message    []byte
	unblinder  []byte
}

func (e *Employee) GetPub() rsa.PublicKey {
	return e.key.PublicKey
}

func NewEmployee(signerskey *rsa.PublicKey) *Employee {
	key, err := rsa.GenerateKey(rand.Reader, Keysize)
	if err != nil {
		panic(err)
	}
	return &Employee{key, signerskey, nil, nil}
}

func (e *Employee) SetMessage(message []byte) {
	e.message = message
}

// employee salary blinding function
func (e *Employee) BlindSalary(message []byte) (blind, sig []byte, err error) {
	e.message = message

	// We do a SHA256 full-domain-hash expanded to 1536 bits (3/4 the key size)
	hashed := fdh.Sum(crypto.SHA256, Hashize, message)

	// Blind the hashed message
	blind, unblinder, err := rsablind.Blind(e.signerskey, hashed)
	if err != nil {
		panic(err)
	}
	e.unblinder = unblinder

	sig, err = SignPSS(blind, e.key)
	return blind, sig, err
}

// employee unblinds and checks sig
func (e *Employee) Unblind(blindSig []byte) ([]byte, error) {
	// Unblind the signature
	unBlindedSig := rsablind.Unblind(e.signerskey, blindSig, e.unblinder)

	// verify the sig
	err = e.VerifySallary(e.message, unBlindedSig, e.signerskey)
	if err != nil {
		return ErrSlice, err
	}
	return unBlindedSig, err
}

func (e *Employee) VerifySallary(message, sig []byte, signerspubkey *rsa.PublicKey) error {
	return VerifySallary(message, sig, e.signerskey)
}

/*********************
	   Signer
**********************/
type Signer struct {
	key       *rsa.PrivateKey
	employees map[rsa.PublicKey]bool
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

func (s *Signer) SignSalary(blinded, bsig []byte, pubkey *rsa.PublicKey) (sig []byte, err error) {
	err = s.authMessage(blinded, bsig, pubkey)
	if err != nil {
		panic(err)
	}
	return rsablind.BlindSign(s.key, blinded)
}

func (s *Signer) AddEmployees(pubkeys []rsa.PublicKey) {
	s.employees = make(map[rsa.PublicKey]bool, len(pubkeys))

	for _, pk := range pubkeys {
		s.employees[pk] = false
	}
}

func (s *Signer) authMessage(message, sig []byte, pubkey *rsa.PublicKey) error {
	val, ok := s.employees[*pubkey]
	if !ok {
		panic("bad employee")
	}
	if val {
		panic("Employee already sent message")
	}
	return VerifyPSS(message, sig, pubkey)
}
