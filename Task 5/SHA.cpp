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

// openssl library
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

// #ifdef BUILD_DLL
// #define EXPORT __attribute__((visibility("default")))
// #else
// #define EXPORT
// #endif
// EXPORT void hashes(const char *algo, const char *input_filename, const char *output_filename);

void handleOpenSSLErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void hash(const std::string& hash_function, const std::string& inputFile, const std::string& outputFile) {
    const EVP_MD* md = nullptr;
    unsigned int length = 0;

    if (hash_function == "sha224") {
        md = EVP_sha224();
    } 
    else if (hash_function == "sha256") {
        md = EVP_sha256();
    } 
    else if (hash_function == "sha384") {
        md = EVP_sha384();
    } 
    else if (hash_function == "sha512") {
        md = EVP_sha512();
    } 
    else if (hash_function == "sha3-224") {
        md = EVP_sha3_224();
    } 
    else if (hash_function == "sha3-256") {
        md = EVP_sha3_256();
    } 
    else if (hash_function == "sha3-384") {
        md = EVP_sha3_384();
    } 
    else if (hash_function == "sha3-512") {
        md = EVP_sha3_512();
    } 
    else if (hash_function == "shake128") {
        md = EVP_shake128();
        std::cout << "Enter output length for SHAKE128: ";
        std::cin >> length;
    } 
    else if (hash_function == "shake256") {
        md = EVP_shake256();
        std::cout << "Enter output length for SHAKE256: ";
        std::cin >> length;
    } 
    else {
        std::cerr << "Unsupported hash function: " << hash_function << std::endl;
        return;
    }

    std::string plain;
    std::cout << "Choose input method:\n";
    std::cout << "1. Input from screen\n";
    std::cout << "2. Input from file\n";
    std::cout << "Your choice: ";
    int inputChoice;
    std::cin >> inputChoice;
    std::cin.ignore();

    switch (inputChoice) {
        case 1:
        {
            std::cout << "Enter plain text: ";
            std::getline(std::cin, plain);
            break;
        }
        case 2:
        {
            std::ifstream infile(inputFile);
            if (!infile) {
                std::cerr << "Error opening input file: " << inputFile << std::endl;
                return;
            }
            plain.assign((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
            infile.close();
            break;
        }
        default:
            std::cerr << "Invalid choice. Please choose 1 or 2." << std::endl;
            exit(1);
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    unsigned char* md_value;
    unsigned int md_len;

    if (hash_function == "shake128" || hash_function == "shake256") {
        if (length == 0) {
            std::cerr << "Length must be specified for SHAKE functions" << std::endl;
            return;
        }
        md_value = new unsigned char[length];
    } else {
        md_value = new unsigned char[EVP_MAX_MD_SIZE];
    }

    if (!mdctx) handleOpenSSLErrors();

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) handleOpenSSLErrors();
    if (EVP_DigestUpdate(mdctx, plain.c_str(), plain.length()) != 1) handleOpenSSLErrors();

    if (hash_function == "shake128" || hash_function == "shake256") {
        if (EVP_DigestFinalXOF(mdctx, md_value, length) != 1) handleOpenSSLErrors();
        md_len = length;
    } else {
        if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) handleOpenSSLErrors();
    }

    EVP_MD_CTX_free(mdctx);

    std::string hash_hex;
    for (unsigned int i = 0; i < md_len; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", md_value[i]);
        hash_hex += buf;
    }

    delete[] md_value;

    std::ofstream outfile(outputFile);
    if (!outfile) {
        std::cerr << "Error opening output file: " << outputFile << std::endl;
        return;
    }

    outfile << hash_hex << std::endl;
    outfile.close();

    std::cout << "Digest written to " << outputFile << std::endl;
}

int main(int argc, char *argv[]) {
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
        std::cerr << argv[0] << " hash <hashFunction> <inputFile> <outputFile>\n";
        std::cerr << argv[0] << "hash function: sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512, shake128, shake256\n";
        return 1;
    }

    std::string choice = argv[1];
    
    if (choice == "hash")
    {
        if (argc != 5) {
            std::cerr << "Usage: " << argv[0] << " hash <hashFunction> <inputFile> <outputFile>\n";
            return 1;
        }

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    
        hash(argv[2], argv[3], argv[4]);

        EVP_cleanup();
        ERR_free_strings();
    }

    return 0;
}
