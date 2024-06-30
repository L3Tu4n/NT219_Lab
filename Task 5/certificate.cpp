#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

void printCertificateInfo(X509* cert) {
    char* subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);

    std::cout << "=== Certificate Information ===" << std::endl;
    std::cout << "Subject: " << subj << std::endl;
    std::cout << "Issuer: " << issuer << std::endl;

    const ASN1_TIME* notBefore = X509_get0_notBefore(cert);
    const ASN1_TIME* notAfter = X509_get0_notAfter(cert);

    BIO* bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, notBefore);
    char buffer[128];
    int len = BIO_read(bio, buffer, sizeof(buffer) - 1);
    buffer[len] = '\0';
    std::cout << "Valid From: " << buffer << std::endl;

    ASN1_TIME_print(bio, notAfter);
    len = BIO_read(bio, buffer, sizeof(buffer) - 1);
    buffer[len] = '\0';
    std::cout << "Valid To: " << buffer << std::endl;

    BIO_free(bio);

    int sig_nid = X509_get_signature_nid(cert);
    std::cout << "Signature Algorithm: " << OBJ_nid2ln(sig_nid) << std::endl;

    OPENSSL_free(subj);
    OPENSSL_free(issuer);
    std::cout << "===============================" << std::endl;
}

EVP_PKEY* validateCertificateSignature(const std::string& certFile) {
    FILE* fp = fopen(certFile.c_str(), "rb");
    if (!fp) {
        std::cerr << "Error opening file: " << certFile << std::endl;
        return nullptr;
    }

    X509* cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert) {
        std::cerr << "Error loading certificate from file: " << certFile << std::endl;
        return nullptr;
    }

    printCertificateInfo(cert);

    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        std::cerr << "Error extracting public key from certificate." << std::endl;
        X509_free(cert);
        return nullptr;
    }

    // Verify signature
    int result = X509_verify(cert, pubkey);
    X509_free(cert);

    if (result != 1) {
        std::cerr << "Certificate signature verification failed." << std::endl;
        EVP_PKEY_free(pubkey);
        return nullptr;
    }

    std::cout << "Certificate signature verified successfully." << std::endl;
    return pubkey;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <certificatefile>" << std::endl;
        return 1;
    }

    const std::string certFile = argv[1];

    EVP_PKEY* pubkey = validateCertificateSignature(certFile);
    if (pubkey) {
        std::cout << "\n=== Subject Public Key ===" << std::endl;
        EVP_PKEY_print_public_fp(stdout, pubkey, 0, NULL);
        EVP_PKEY_free(pubkey);
        std::cout << "==========================" << std::endl;
    } else {
        std::cout << "null" << std::endl;
    }

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
