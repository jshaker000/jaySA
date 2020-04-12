#include <fstream>
#include <iostream>
#include <string>
#include <utility>

#include <getopt.h>
#include <unistd.h>

#include "crypto.h"
#include "base64.h"

static constexpr int PUB_KEY  = 0;
static constexpr int PRIV_KEY = 1;

int main(int argc, char** argv)
{
    //parse input flags
    bool encrypt = 0;
    bool sign    = 0;
    bool decrypt = 0;
    bool verify  = 0;
    bool base64  = 0;
    bool help    = 0;

    std::string pubk   = "";
    std::string privk  = "";
    std::string in_f   = "";
    std::string out_f  = "";
    std::string genkey = "";

    while (1)
    {
        int c;
        int option_index = 0;
        static constexpr struct option long_options[] = {
            { "encrypt", no_argument,       0, 'e'       },
            { "sign"   , no_argument,       0, 's'       },
            { "verify" , no_argument,       0, 'v'       },
            { "decrypt", no_argument,       0, 'd'       },
            { "b64"    , no_argument,       0, 'b'       },
            { "base64" , no_argument,       0, 'b'       },
            { "pubk"   , required_argument, 0,  PUB_KEY  },
            { "privk"  , required_argument, 0,  PRIV_KEY },
            { "in-f"   , required_argument, 0, 'i'       },
            { "out-f"  , required_argument, 0, 'o'       },
            { "gen-key", required_argument, 0, 'g'       },
            { "help"   , no_argument,       0, 'h'       },
            { nullptr  ,           0,       0,  0        }
        };

        c = getopt_long(argc, argv, "esvdbhg:i:o:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
            case 'e':
                if (decrypt == 1 || verify == 1)
                {
                    std::cerr << "Invalid argument combination." << std::endl;
                    return 1;
                }
                encrypt = true;
                break;

            case 's':
                if (decrypt == 1 || verify == 1)
                {
                    std::cerr << "Invalid argument combination." << std::endl;
                    return 1;
                }
                sign = true;
                break;

            case 'd':
                if (encrypt == 1 || sign == 1)
                {
                    std::cerr << "Invalid argument combination." << std::endl;
                    return 1;
                }
                decrypt = true;
                break;

            case 'v':
                if (encrypt == 1 || sign == 1)
                {
                    std::cerr << "Invalid argument combination." << std::endl;
                    return 1;
                }
                verify = true;
                break;

            case 'b':
                base64 = true;
                break;

            case PUB_KEY:
                pubk = optarg;
                break;

            case PRIV_KEY:
                privk = optarg;
                break;

            case 'i':
                in_f = optarg;
                break;

            case 'o':
                out_f = optarg;
                break;

            case 'g':
                genkey = optarg;
                break;

            case 'h':
                help = true;
                break;
        }
    }

    // decide what to do based on flags received and
    // check there are no invalid option combinations
    if (help)
    {
        std::cerr << "Please refer to the manpage for help." << std::endl;
        return 0;
    }

    if (genkey.size() > 0)
    {
        std::cerr << "Generating keypair with name " << genkey << std::endl;
        return crypto::rsa_genkeypair (genkey);
    }

    if (encrypt && pubk.size() == 0)
    {
        std::cerr << "No public key to encrypt with." << std::endl;
        return 1;
    }

    if (verify && pubk.size() == 0)
    {
        std::cerr << "No public key to verify with." << std::endl;
        return 1;
    }

    else if (decrypt && privk.size() == 0)
    {
        std::cerr << "No private key to decrypt with." << std::endl;
        return 1;
    }

    else if (sign && privk.size() == 0)
    {
        std::cerr << "No private key to sign with." << std::endl;
    }

    if (encrypt && !sign)
    {
        privk = "";
    }

    if (decrypt && !verify)
    {
        pubk = "";
    }

    if(!encrypt && !decrypt)
    {
        std::cerr << "No work to do." << std::endl;
        return 200;
    }

    //decide where to get input from
    std::string in, out;

    if(isatty(STDIN_FILENO) == 0 && in_f == "")
    {
        in_f = "/dev/stdin";
    }

    if (in_f.size())
    {
        std::fstream infile(in_f.c_str(), std::ios::in | std::ios::binary);

        if (infile.fail())
        {
            std::cerr << "Failed to open input file \"" <<  in_f << "\"." << std::endl;
            return 2;
        }

        std::string s((std::istreambuf_iterator<char>(infile)),
                       std::istreambuf_iterator<char>());
        in = std::move(s);
        infile.close();
    }

    else
    {
        std::cerr << "Print your message to be encrypted/decypted\n> " << std::flush;
        std::getline(std::cin, in);
    }

    //encrypt / decrypt
    if (encrypt)
    {
        if (crypto::rsa_encrypt_sign(in, pubk, privk, out))
        {
            std::cerr << "ERROR ENCRYPTING OR SIGNING." << std::endl;
            return 3;
        }
        if(base64)
        {
            out = base64::base64_encode(reinterpret_cast<const unsigned char*>(out.c_str()), out.size());
        }
    }

    else if (decrypt)
    {
        if(base64)
        {
            in = base64::base64_decode(in);
        }
        if (crypto::rsa_decrypt_verify(in, pubk, privk, out))
        {
            std::cerr << "ERROR DECRYPTING OR VERIFYING." << std::endl;
            return 4;
        }
    }

    //print out
    if (out_f.size() == 0)
    {
        out_f = "/dev/stdout";
    }

    std::fstream outfile(out_f.c_str(), std::ios::out | std::ios::binary);
    if(outfile.fail())
    {
        std::cerr << "Failed to open output file \"" <<  out_f << "\"" << std::endl;
        return 5;
    }
    outfile.write(out.c_str(), out.size());

    return 0;
}
