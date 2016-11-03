Protocol for anonymous salary reporting based on an e-voting scheme.

Suppose a group of N employees want to compare their pay by revealing how much they make.
But each employee doesn't want the others to know what her individual salary is.

Here are some requirements they want:
* Anonymity. No one can associate a reported salary with an employee.
* Only those who are authorized can report their salary.
* Each employees can only report once.
* Verifiability. Every employee can verify they're own salary was reported publicly.

So they decide to do something like this:

## setup
They prepare as a group:
* agree who the N employees who will participate are
* agree on a third party who creates a new RSA key specifically for this event
* agree on an anonymous forum to post the salaries
* every employee generates an RSA key pair
* give the third party the authorized employee's public keys

# blinding
Then each employee does a few things:
* writes her salary down
* hashes the salary
* blinds the hash with the third parties public key and her own secret
* signs this blinded hash with her own public key
* sends this signed blinded hash to the 3rd party 

# signing
The third party then takes each message and:
* checks the key belongs to an authorized employee
* checks this employee has not already submitted a message
* checks the signature
* signs the message
* returns the signature to whoever sent it

# verifying
Each employee get a blinded signature back, she then:
* unblinds the signature
* checks the validity of the unblinded signature with the third parties public key and the hash of her salary
* posts the salary on the anonymous forum
* checks out the other peoples salaries
* complains to boss
