#include <iostream>
using std::cerr;
using std::cout;
using std::endl;
using std::cin;

#include <exception>
using std::exception;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <locale>
#include <cctype>
#include <fstream>

// CryptoPP library
#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/eccrypto.h>
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include <cryptopp/oids.h>

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/base64.h>
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::ArraySink;

#include <cryptopp/sha.h>
using CryptoPP::SHA256;

void generateKeys(const std::string& formatKey, const std::string& privateKeyFile, const std::string& publicKeyFile) {
    AutoSeededRandomPool prng;

    // Generate private key
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    privateKey.Initialize(prng, CryptoPP::ASN1::secp256k1());

    // Generate public key
    ECDSA<ECP, SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    if (formatKey == "BER") {
        FileSink priBer(privateKeyFile.c_str());
        privateKey.Save(priBer);

        FileSink pubBer(publicKeyFile.c_str());
        publicKey.Save(pubBer);
    } 
    else if (formatKey == "PEM") {
        // Save private key as PEM
        std::string privateKeyStr;
        privateKey.Save(StringSink(privateKeyStr).Ref());

        // Encode private key as Base64
        std::string encodedPrivateKey;
        StringSource(privateKeyStr, true, new Base64Encoder(new StringSink(encodedPrivateKey)));

        // Write private key to file
        std::ofstream privateFileOut(privateKeyFile.c_str());

        // privateFileOut << "-----BEGIN PRIVATE KEY-----" << std::endl;
        privateFileOut << encodedPrivateKey;
        // privateFileOut << "-----END PRIVATE KEY-----";
        privateFileOut.close();

        // Save public key as PEM
        std::string publicKeyStr;
        publicKey.Save(StringSink(publicKeyStr).Ref());

        // Encode public key as Base64
        std::string encodedPublicKey;
        StringSource(publicKeyStr, true, new Base64Encoder(new StringSink(encodedPublicKey)));

        // Write public key to file
        std::ofstream publicFileOut(publicKeyFile.c_str());

        // publicFileOut << "-----BEGIN PUBLIC KEY-----" << std::endl;
        publicFileOut << encodedPublicKey;
        // publicFileOut << "-----END PUBLIC KEY-----";
        publicFileOut.close();
    } 
    else {
        cerr << "Invalid key format. Please choose BER or PEM." << endl;
        exit(1);
    }

    std::cout << "Keys generated and saved to files (" << formatKey << ").\n";
}

void signMessage(const std::string& formatKey, const std::string& privateKeyFile, const std::string& messageFile, const std::string& signatureFile) {
    AutoSeededRandomPool prng;

    // Load private key
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    if (formatKey == "BER") {
        FileSource privFile(privateKeyFile.c_str(), true);
        privateKey.Load(privFile);
    } 
    else if (formatKey == "PEM") {
        std::string pemKey;
        FileSource(privateKeyFile.c_str(), true, new Base64Decoder(new StringSink(pemKey)));
        privateKey.BERDecode(StringSource(pemKey, true).Ref());
    } 
    else {
        cerr << "Invalid key format. Please choose BER or PEM." << endl;
        exit(1);
    }

    std::string message;
	cout << "Choose input method:\n";
	cout << "1. Input from screen\n";
	cout << "2. Input from file\n";
	cout << "Your choice: ";
	int inputChoice;
	cin >> inputChoice;
	cin.ignore();

	switch (inputChoice) 
	{
		case 1: 
		{
			cout << "Enter message text: ";
			getline(cin, message);
			break;
		}
		case 2: 
		{
            FileSource(messageFile.c_str(), true, new StringSink(message));
			break;
		}
		default:
			cerr << "Invalid choice. Please choose 1 or 2." << endl;
			exit(1);
	}

    // Sign message
    ECDSA<ECP, SHA256>::Signer signer(privateKey);

    std::string signature;
    StringSource (message, true,
        new SignerFilter(prng, signer,
            new StringSink(signature)
        )
    );
    StringSource(message, true, new FileSink(messageFile.c_str()));
    
    // Save signature
    FileSink sigFile(signatureFile.c_str());
    sigFile.Put((const CryptoPP::byte*)&signature[0], signature.size());

    std::cout << "Message signed and signature saved to file.\n";
}

void verifyMessage(const std::string& formatKey, const std::string& publicKeyFile, const std::string& messageFile, const std::string& signatureFile) {
    // Load public key
    ECDSA<ECP, SHA256>::PublicKey publicKey;
    if (formatKey == "BER") {
        FileSource pubFile(publicKeyFile.c_str(), true);
        publicKey.Load(pubFile);
    } 
    else if (formatKey == "PEM") {
        std::string pemKey;
        FileSource(publicKeyFile.c_str(), true, new Base64Decoder(new StringSink(pemKey)));
        publicKey.BERDecode(StringSource(pemKey, true).Ref());
    } 
    else {
        cerr << "Invalid key format. Please choose BER or PEM." << endl;
        exit(1);
    }

    // Load message
    std::string message;
    FileSource msgFile(messageFile.c_str(), true, new StringSink(message));

    // Load signature
    std::string signature;
    FileSource sigFile(signatureFile.c_str(), true, new StringSink(signature));

    // Verify signature
    ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

    bool result = false;
    StringSource (signature + message, true,
        new SignatureVerificationFilter(
            verifier,
            new ArraySink((CryptoPP::byte*)&result, sizeof(result))
        )
    );

    if (result) {
        cout << "Signature is valid. The message has been verified successfully.\n";
    } 
    else {
        cout << "Signature is invalid. The message could not be verified or the message has been altered.\n";
    }
}

int main(int argc, char* argv[]) {
    #ifdef __linux__
        std::locale::global(std::locale("C.utf8"));
    #endif
    #ifdef _WIN32
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
    #endif

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <option>\n";
        std::cerr << "Options:\n";
        std::cerr << argv[0] << " genkey <formatKey> <privateKeyFile> <publicKeyFile\n";
        std::cerr << argv[0] << " sign <formatKey> <privateKeyFile> <messageFile> <signatureFile>\n";
        std::cerr << argv[0] << " verify <formatKey> <publicKeyFile> <messageFile> <signatureFile>\n";
        std::cerr << "format key: BER or PEM\n";
        return 1;
    }

    string choice = argv[1];

    if (choice == "genkey") {
        if (argc != 5) {
            std::cerr << "Usage: " << argv[0] << " genkey <formatKey> <privateKeyFile> <publicKeyFile>\n";
            return 1;
        }
        generateKeys(argv[2], argv[3], argv[4]);
    }
    else if (choice == "sign") {
        if (argc != 6) {
            std::cerr << "Usage: " << argv[0] << " sign <formatKey> <privateKeyFile> <message> <signatureFile>\n";
            return 1;
        }
        signMessage(argv[2], argv[3], argv[4], argv[5]);
    }
    else if (choice == "verify") {
        if (argc != 6) {
            std::cerr << "Usage: " << argv[0] << " verify <formatKey> <publicKeyFile> <messageFile> <signatureFile>\n";
            return 1;
        }
        verifyMessage(argv[2], argv[3], argv[4], argv[5]);
    }

    return 0;
}
