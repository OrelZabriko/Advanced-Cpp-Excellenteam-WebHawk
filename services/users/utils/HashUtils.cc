#include "HashUtils.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>

std::string HashUtils::hashPassword(const std::string &password) {
    CryptoPP::SHA256 hash;
    std::string digest;
    CryptoPP::StringSource s(password, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest)
            )
        )
    );
    return digest;
}

bool HashUtils::verifyPassword(const std::string &password, const std::string &storedHash) {
    return hashPassword(password) == storedHash;
}