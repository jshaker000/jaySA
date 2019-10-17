# jaySA

## Purpose:
The purpose of this program is to be a simple, easy to understand and use wrapper of OPENSSL RSA encryption, decryption, signing, verifying, and key generation. The documentation of using the CLI tools in OPENSSL is poor.

The source code also can demonstrate and serve as an example of how to use the OPENSSL EVP functions.

Notes:

1) It is recommended when encrypting fodlers or large groups of files to make a tarball/zip **first** then encrypt, because encryption is computationally expensive
2) Currently I load the entire file to be encrypted into RAM at once so if your file is too big this may fail.

## Cryptographic Methods:

This program uses OpenSSL's "EVP" functions to encrypt and decrypt. The process has several steps.

First, it will generate a random symetric encryption key (in this case, aes_256_cbc). Then it will generate a random iv, and symetric key.
It will use the iv & symetric key to encrypt the enctire message, then use RSA to asymetrically encrypt the symetric key. This hybrid approach allows
you to get the benefits of RSA without the downsides (slow, can only encrypt messages up to key_length bits, etc).  

The whole message then, the asymetrically encrypted symetric key, the plain iv, and the symetrically encrypted message, is then signed if desired and sent. 

Implementation is in *src/include/crypto.h* and *src/include/crypto.cpp* and you can read the man pages on OpenSSL EVP for more details.

### An Aside on Asymetric Encryption vs Symetric Encryption:

This system uses a public key / private key system. You generate a publickey / private key pair. You share your public to anyone, who can 
encrypt messages with it that can only be decrypted with your private key. You can also sign messages with your private key that can only be verified
with your public key. This gives you a way to encrypt messages with people without having to manage and share a secrret key between you.
It also gives you a way to verify your identity. For this to work, you must trust that the person you are communicating with is the REAL OWNER of their private key, and that there is no MITM attack. (try to verify it with them out of channel)

Because each message will have its own random AES key and IV, so as long as your private key stays safe, all of the messages should be too.
Cracking one message's AES should not allow any others to be cracked.

You must be careful to guard your private key and NEVER SHARE IT. People with it can decrypt all messages sent to you and can impersonate your identity.

## Compile & Install:
Clone the repository and run **make && make install** from the *src/* directory. 
This will compile the program and copy it to your **$PATH**, and install the man page.
Depending on your system, *make install* may require administrative privileges.

    $ make && make install

To uninstall the program, run:

    $ make clean && make uninstall

### Man Page:
Upon runing **make install**, the man page should be copied to your local manpage directory. but if it fails may have to either 
adjsut your **$MANPATH** or change the make file.
If everything succeeds you can can now see examples and more detailed information using

    man jaySA

If installation of the manpage fails, you can still see the manpage locally by running: 

    man src/./jaySA.man

while in this directory.

## Usage:

    $ jaySA -h[elp]
    $ jaySA --gen-key={key name}
    $ jaySA -e[ncrypt] --pubk=<path to public key> [options]
    $ jaySA -d[ecrypt] --privk=<path to private key> [options]

### Options:

-s    sign the message. Can only be used in **encrypt** mode and requries a private key to be passed in to sign with using **--privk=**

-v    verify the message's signature. Can only be used in **decrypt** mode and requries a public key to be passed in to verify with using **--pubk=**

-i    path of input file to work with. Default is stdin

-o    path of input file to write to. Default is stdout

-b    convert the encrypted message to base64 before writing it / decode the encrypted message from base64 before decrypting
      must be using on both sides, else decryption will fail.
      Base64 is useful because it turns the output into all printable characters, but it also makes the output quite a bit bigger
      It is useful to send in plaintext, but attaching a file of binary data may be preferable


## Examples:

### Example 1:
Generate keys "apple.pub.pem" and "apple.priv.pem"

    $ jaySA --gen-key=apple

### Example 2:
Encrypt  contents of "file" for "apple.pub.pem" and sign with "apple.priv.pem". Store in "out.enc"

    $ jaySA -es --pubk=apple.pub.pem --privk=apple.priv.pem  -i file -o out.enc

### Example 3:
Decrypt the contents  of base64 encoded and encrypted "out.enc" with key "apple.priv.pem". Print reseult to stdout

    $ jaySA -db --privk=apple.priv.pem  -i out.enc
