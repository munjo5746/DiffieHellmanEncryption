# DiffieHellmanEncryption
This project is the implementation of Diffie-Hellman key exchange algorithm applied to a simple chat program.
The python library pycrypto is required to test it.

## algorithm
The idea of the algorithm is that it makes easy to encrypt but hard to decrypt. The Diffie-Hellman key exchange algorithm uses the property of multiplicative group prime modulo. The idea is that two groups that will communicate in secret will agree on public keys, primitive root and prime modulo. These two groups choose their own private key and take the primitive root to the power of the secret key modulo prime. Then, they send the result to each other, and calculate the result to the power of their private key modulo prime. This results with same decrypted key.
