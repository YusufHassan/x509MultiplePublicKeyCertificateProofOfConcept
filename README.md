# x509 Multiple Public Key Certificate Proof Of Concept
This is a minimal implementation of the following IETF draft: Multiple Public-Key Algorithm X.509 Certificates draft-truskovsky-lamps-pq-hybrid-x509-01.

Each time the main class is ran, RSA and Sphincs keys are generated and written to the filesystem. A Multiple Public Key is created and written to the filesystem. The certificate is then read from the file system together with its keys and gets verified using those keys. Both the alternative and conventional signature gets verified.
