package blinding

import (
	"crypto/rsa"
	"testing"
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
	signer.AddEmployees(keys)
	return signer, employees
}

func TestOneSigPerEmployee(t *testing.T) {
	// test employee can't get two sigs
	signer, employees := setup(1)
	employee := employees[0]
	bmsg, _ := employee.BlindSalary([]byte("message one"))

	// try to sign twice
	_, err := signer.SignSalary(bmsg)
	if err != nil {
		t.Fatal(err)
	}

	_, err = signer.SignSalary(bmsg)
	if err == nil {
		t.Fatal("Signer managed to sign the same employee twice")
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
		t.Fatal("Signer managed to sign unregistered employee")
	}
}

func TestEmployeeCanOnlyBlindOnce(t *testing.T) {
	_, employees := setup(1)
	employee := employees[0]
	employee.BlindSalary([]byte("once"))
	_, err := employee.BlindSalary([]byte("twice"))
	if err == nil {
		t.Fatal("Employee managed to sign twice")
	}
}
