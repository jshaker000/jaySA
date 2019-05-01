# jaySA

## Purpose:
The purpose of this program is to be a simple, easy to understand and use wrapper of OPENSSL RSA encryption, decryption, signing, verifying, and key generation. The documentation of using the CLI tools in OPENSSL is poor.

The source code also can demonstrate and serve as an example of how to use the OPENSSL EVP functions.

## Compile & Install:
Clone the repository and run **make && make install** from the src/ directory. 
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

    man src/./jaySA

while in this directory.

## Usage:

    $ jaySA -h[elp]
    $ jaySA --gen-key={key name}
    $ jaySA -e[ncrypt] --pubk=<path to public key> [options]
    $ jaySA -d[ecrypt] --privk=<path to private key> [options]

###Options:

-s    sign the message. Can only be used in **encrypt** mode and requries a private key to be passed in to sign with using **--privk=**

-v    verify the message's signature. Can only be used in **decrypt** mode and requries a public key to be passed in to verify with using **--pubk=**

-i    path of input file to work with. Default is stdin

-o    path of input file to write to. Default is stdout

-b    convert the encrypted message to base64 before writing it / decode the encrypted message from base64 before decrypting
      must be using on both sides, else decryption will fail


## Examples:

###Example 1:
Generate keys "apple.pub.pem" and "apple.priv.pem"

    $ jaySA --gen-key=apple

###Example 2:
Encrypt  contents of "file" for "apple.pub.pem" and sign with "apple.priv.pem". Store in "out.enc"

    $ jaySA -es --pubk=apple.pub.pem --privk=apple.priv.pem  -i file -o out.enc

###Example 3:
Decrypt the contents  of base64 encoded and encrypted "out.enc" with key "apple.priv.pem". Print reseult to stdout

    $ jaySA -db --privk=apple.priv.pem  -i out.enc
