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

type BlindedMessage struct {
	Blinded []byte
	Sig		[]byte
	PublicKey	rsa.PublicKey
}

/*********************
	   Employee
**********************/
type Employee struct {
	key        *rsa.PrivateKey
	signerskey *rsa.PublicKey
	message    []byte
	unblinder  []byte
	PublicKey *rsa.PublicKey
}

func NewEmployee(signerskey *rsa.PublicKey) *Employee {
	key, err := rsa.GenerateKey(rand.Reader, Keysize)
	if err != nil {
		panic(err)
	}
	return &Employee{key, signerskey, nil, nil, &key.PublicKey}
}

// employee salary blinding function
func (e *Employee) BlindSalary(message []byte) (*BlindedMessage, error) {
	e.message = message

	// We do a SHA256 full-domain-hash expanded to 1536 bits (3/4 the key size)
	hashed := fdh.Sum(crypto.SHA256, Hashize, message)

	// Blind the hashed message
	blind, unblinder, err := rsablind.Blind(e.signerskey, hashed)
	if err != nil {
		panic(err)
	}
	e.unblinder = unblinder

	sig, err := SignPSS(blind, e.key)
	return &BlindedMessage{blind, sig, *e.PublicKey}, err
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
	PublicKey *rsa.PublicKey
}

func NewSigner() *Signer {
	key, err := rsa.GenerateKey(rand.Reader, Keysize)
	if err != nil {
		panic(err)
	}
	return &Signer{key, nil, &key.PublicKey}
}

func (s *Signer) AddEmployees(pubkeys []rsa.PublicKey) {
	s.employees = make(map[rsa.PublicKey]bool, len(pubkeys))

	for _, pk := range pubkeys {
		s.employees[pk] = false
	}
}

func (s *Signer) SignSalary(message *BlindedMessage) (sig []byte, err error) {
	err = s.authMessage(message)
	if err != nil {
		panic(err)
	}
	return rsablind.BlindSign(s.key, message.Blinded)
}

func (s *Signer) authMessage(message *BlindedMessage) error {
	val, ok := s.employees[message.PublicKey]
	if !ok {
		panic("bad employee")
	}
	if val {
		panic("Employee already sent message")
	}
	return VerifyPSS(message.Blinded, message.Sig, &message.PublicKey)
}
