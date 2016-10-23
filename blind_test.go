package blinding

import (
    "crypto/rand"
    "crypto/rsa"
	"testing"
)

func Test(t * testing.T) {
    // Set up the signer
    key, _ := rsa.GenerateKey(rand.Reader, Keysize)

	// Set up the employee
	message := []byte("a living wage")

    // employee blinds the message
    blinded, unblinder, err := BlindSalary(message, &key.PublicKey)
    if err != nil {
        panic(err)
    }
	// employee sends it to the signer

    // signer signs the blinded message
    blindsig, err := SignSalary(blinded, key)
    if err != nil {
        panic(err)
    }
	// signer returns the signature to the employee

	// employee unblinds the signature and checks it against her original message
	sig, err := Unblind(message, blindsig, unblinder, &key.PublicKey)
	if err != nil {
		panic(err)
	}
	// employee posts the salary and sign somewhere annonymously

	// someone checks the salaries signature
	err = VerifySallary(message, sig, &key.PublicKey)
	if err != nil {
		panic(err)
	}
}
