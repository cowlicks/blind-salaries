package blinding

import (
	"crypto/rsa"
	"testing"
)

func TestIntegration(t *testing.T) {
	// Set up the signer
	signer := NewSigner()

	// Set up the employee
	salary := []byte("a living wage")
	employee := NewEmployee(signer.PublicKey)

	// add employees to signer
	signer.AddEmployees([]rsa.PublicKey{*employee.PublicKey})

	// employee blinds the salary
	blindedmessage, err := employee.BlindSalary(salary)
	if err != nil {
		panic(err)
	}
	// employee sends it to the signer

	// signer signs the blinded salary
	blindsig, err := signer.SignSalary(blindedmessage)
	if err != nil {
		panic(err)
	}
	// signer returns the signature to the employee

	// employee unblinds the signature and checks it against her original salary
	sig, err := employee.Unblind(blindsig)
	if err != nil {
		panic(err)
	}
	// employee posts the salary and sign somewhere annonymously

	// someone checks the salaries signature
	err = employee.VerifySallary(salary, sig, signer.PublicKey)
	if err != nil {
		panic(err)
	}
}
