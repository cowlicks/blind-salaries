package blinding

import (
	"crypto/rsa"
	"testing"
	"fmt"
)

func TestIntegration(t *testing.T) {
	// Set up the signer
	signer, _ := NewSigner()

	// Set up the employee
	salary := []byte("a living wage")
	employee, _ := NewEmployee(signer.PublicKey)

	// add employees to signer
	signer.AddEmployees([]rsa.PublicKey{*employee.PublicKey})

	// employee blinds the salary
	blindedmessage, err := employee.BlindSalary(salary)
	if err != nil {
		t.Fatal(err)
	}
	// employee sends it to the signer

	// signer signs the blinded salary
	blindsig, err := signer.SignSalary(blindedmessage)
	if err != nil {
		t.Fatal(err)
	}
	// signer returns the signature to the employee

	// employee unblinds the signature and checks it against her original salary
	sig, err := employee.Unblind(blindsig)
	if err != nil {
		t.Fatal(err)
	}
	// employee posts the salary and sign somewhere annonymously

	// someone checks the salaries signature
	err = employee.VerifySallary(salary, sig, signer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
}


// Creates a signer, some employees, and registers them
func setup(nemployees int) (*Signer, []*Employee) {
	signer, _ := NewSigner()

	employees := make([]*Employee, nemployees)
	keys := make([]rsa.PublicKey, nemployees)

	for i := 0; i < nemployees; i++ {
		e, _ := NewEmployee(signer.PublicKey)
		employees[i] = e
		keys[i] = *e.PublicKey
	}
	return signer, employees
}


func TestOneSigPerEmployee(t *testing.T) {
	// test employee can't get two sigs
	signer, employees := setup(1)
	employee := employees[0]
	bmsg, _ := employee.BlindSalary([]byte("message one"))

	// try to sign twice
	signer.SignSalary(bmsg)
	_, err := signer.SignSalary(bmsg)
	if err == nil {
		t.Fatal()
	}
}

func TestOnlyRegisteredEmployees(t *testing.T) {
	// test employee can't get two sigs
	signer, _ := setup(0)
	employee, _ := NewEmployee(signer.PublicKey)
	bmsg, _ := employee.BlindSalary([]byte("message one"))

	// try to sign while not registered
	_, err := signer.SignSalary(bmsg)
	if err == nil {
		t.Fatal()
	}
}

func TestEmployeeCanOnlyBlindOnce(t *testing.T) {
	_, employees := setup(1)
	employee := employees[0]
	employee.BlindSalary([]byte("once"))
	_, err = employee.BlindSalary([]byte("twice"))
	if err == nil {
		t.Fatal()
	}
}

func TestREADME(t *testing.T) {
	// Set up the signer
	signer, _ := NewSigner()

	// Set up the employees
	alice, _ := NewEmployee(signer.PublicKey)
	bob, _ := NewEmployee(signer.PublicKey)

	// add employees to signer
	signer.AddEmployees([]rsa.PublicKey{*alice.PublicKey, *bob.PublicKey})

	// Alice and Bob write down their salaries
	aliceSal := []byte("Below the glass ceiling")
	bobSal   := []byte("A living wage")

	// They blind their salaries and sign them.
	aliceBlindMsg, _	:= alice.BlindSalary(aliceSal)
	bobBlindMsg, _		:= bob.BlindSalary(bobSal)

	// The signer verifies each message is authorized, and signs it.
	// The message is encrypted (blinded). The signer cannot read it.
	aliceBlindSig, _	:= signer.SignSalary(aliceBlindMsg)
	bobBlindSig, _		:= signer.SignSalary(bobBlindMsg)

	// Alice and bob unblind their signature
	aliceSig, _	:= alice.Unblind(aliceBlindSig)
	bobSig, _   := bob.Unblind(bobBlindSig)

	// They post the salaries and signatures anonymously somewhere
	fmt.Println(FinalMessage(aliceSal, aliceSig))
	fmt.Println(FinalMessage(bobSal, bobSig))
}
