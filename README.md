This package implements a protocol for anonymous salary reporting based on an
e-voting scheme.

Suppose a group of N employees want to compare their pay by revealing how much
they make. But each employee doesn't want the others to know what her
individual salary is.

They could try getting everyone to post their salary annonymously in some forum,
like on a google doc through tor. But then there would be no way of verifying
what was posted  actually came from an employee. Or employees could post multiple
times.

Here are some requirements they want:
* Anonymity. No one can associate a reported salary with an employee.
* Only those who are authorized can report their salary.
* Each employees can only report once.
* Verifiability. Every employee can verify they're own salary was reported publicly.

This package tries to do this, here is a basic example of the usage:

```go
// Set up the signer
signer, _ := NewSigner()

// Set up the employees
alice, _ := NewEmployee(signer.PublicKey)
bob, _ := NewEmployee(signer.PublicKey)

// add employees to signer
signer.AddEmployees([]rsa.PublicKey{*alice.PublicKey,
                                    *bob.PublicKey})

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
```
<hr>
```
salary: Below the glass ceiling
signature: O1k/UWPdtS5A2QFfMUxMwQjPlZIqvv6on27c3kxhW0CaI9MkvmCGTpxyO5a4BZP3jEzeHnvRswEAIGVMNmYZRgUg5suinE1UmPJoOma+92WICJAps50/nRzV6QjoU87zjPN8pNVohxO3zRNnkpRoH0OzDdS+BzjkmZ/GZy5/gXB6VZ9GY4Pn6JeorVG/0OpkHwVaP0PNzpWZ6hheuMpUhAywE9pXQY9F+mF1BmZJg5MOMwTgZ7rAKxnkUjg+3K4SMZ0iZ7lG5EiQOXdXAm+ra3F2Q1WlPtanVKKpPJ6ZsXSSW7s3TkOACa0lhDD5vrRnOGFinuz5QijUMEZ1E7sv2w==

salary: A living wage
signature: WWGMAdfE8ZEavK7Luu+LEu4dwISP0hje7PYqjqfUpCjNOkk+IJDCn8zg1xwHIKq0+G/WIdc5HQ94OSHNO9ARDsZOt3+93SHV0cKUqwnPP3rFsWetqOFr2yUNzD3jHC0iWH85ahROOXJnAGG8eP6AuI2NwduNSpnecJVTISe2maB2DfMeBL9Ja8zG8DJgWzbcYfJ46VbeuRFpbDGL8HuTbDsqf+pfzWieJQVJ1sNCsk8kOmdeSduPNRRxVylKYg8akil8OXbQghG9S0u4J1w/qruFiXprgLCowOXhJWcQWMu43jztSQFOjAb1so2wT/DTymGY6FCQt58w/NDXizbESg==
```

# Protocol

## setup
They prepare as a group:
* agree who the N employees who will participate are
* agree on a third party who creates a new RSA key specifically for this event
* agree on an anonymous forum to post the salaries
* every employee generates an RSA key pair
* give the third party the authorized employee's public keys

## blinding
Then each employee does a few things:
* writes her salary down
* hashes the salary
* blinds the hash with the third parties public key and her own secret
* signs this blinded hash with her own public key
* sends this signed blinded hash to the 3rd party 

## signing
The third party then takes each message and:
* checks the key belongs to an authorized employee
* checks this employee has not already submitted a message
* checks the signature
* signs the message
* returns the signature to whoever sent it

## verifying
Each employee get a blinded signature back, she then:
* unblinds the signature
* checks the validity of the unblinded signature with the third parties public key and the hash of her salary
* posts the salary on the anonymous forum
* checks out the other peoples salaries
* complains to boss
