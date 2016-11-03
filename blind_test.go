package blinding

import (
	"crypto/rsa"
	"testing"
)

func TestIntegration(t *testing.T) {
	// Set up the signer
	signer := NewSigner()
	sigkey := signer.GetPub()
	key := sigkey

	// Set up the employee
	employee := NewEmployee(&sigkey)
	empkey := employee.GetPub()
	message := []byte("a living wage")

	// add employees to signer
	signer.AddEmployees([]rsa.PublicKey{employee.GetPub()})

	// employee blinds the message
	blinded, bsig, err := employee.BlindSalary(message)
	if err != nil {
		panic(err)
	}
	// employee sends it to the signer

	// signer signs the blinded message
	blindsig, err := signer.SignSalary(blinded, bsig, &empkey)
	if err != nil {
		panic(err)
	}
	// signer returns the signature to the employee

	// employee unblinds the signature and checks it against her original message
	sig, err := employee.Unblind(blindsig)
	if err != nil {
		panic(err)
	}
	// employee posts the salary and sign somewhere annonymously

	// someone checks the salaries signature
	err = employee.VerifySallary(message, sig, &key)
	if err != nil {
		panic(err)
	}
}
