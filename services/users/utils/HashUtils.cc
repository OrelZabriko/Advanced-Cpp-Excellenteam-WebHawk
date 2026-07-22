#include "HashUtils.h"
#include <bcrypt/bcrypt.h>

// Cost factor (work factor). Higher = slower = more resistant to brute force.
// 12 is a common default; the project spec doesn't mandate a specific value.
static const int BCRYPT_WORKFACTOR = 12;

std::string HashUtils::hashPassword(const std::string &password) 
{
    char salt[BCRYPT_HASHSIZE];
    char hash[BCRYPT_HASHSIZE];

    // bcrypt_gensalt generates a random salt baked into the salt string itself,
    // so every call produces a different hash even for the same password.
    bcrypt_gensalt(BCRYPT_WORKFACTOR, salt);
    bcrypt_hashpw(password.c_str(), salt, hash);

    return std::string(hash);
}

bool HashUtils::verifyPassword(const std::string &password, const std::string &storedHash) 
{
    // bcrypt_checkpw re-derives the hash using the salt embedded in storedHash
    // and compares in constant time. Returns 0 on match, non-zero otherwise.
    return bcrypt_checkpw(password.c_str(), storedHash.c_str()) == 0;
}