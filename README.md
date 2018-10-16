# Cryptify

*Cryptify* is an Encryption / Decryption framework for easy to use Key generation in Swift. It targets applications, that need encryption and Key exchange for messaging purposes. The goal is to write a framework that can be used by all possible plattforms to generate the neccessary Private keys and store them locally (Keychain or Secure Enclave if possible). In addition to that *Cryptify* can handle _foreign_ Public keys while utilizing the Keychain to manage their persistence.

## Current Progress

*Cryptify* is currently a work in progress. Key Storage and Encryption / Decryption of Data is working on iOS and seems to be free of any errors. Next step is building an easier interface and starting with the integration of a Key-Exchange process.
