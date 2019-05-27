# x509 Multiple Public Key Certificate Proof Of Concept
This is a minimal implementation of the following IETF draft: Multiple Public-Key Algorithm X.509 Certificates draft-truskovsky-lamps-pq-hybrid-x509-01.

Each time the main function is ran, RSA and Sphincs keys are generated. A Multiple Public Key is created and written to the filesystem. The certificate is then read from the file system and gets verified. Both the alternative and conventional signature gets verified.
