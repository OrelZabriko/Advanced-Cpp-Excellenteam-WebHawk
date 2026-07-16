#pragma once

#include <string>

// Generates the API keys issued to developers when they register a backend
// (see Contract B in the API Contracts doc - the example there is
// "whk_live_8f3a..." which is exactly the format this produces).
class ApiKeyGenerator 
{
public:
    // Returns a new random key of the form "whk_live_<32 hex characters>".
    // Not cryptographically hardened beyond std::random_device - fine for
    // a project like this, but note this is NOT a password: it's a bearer
    // credential (see Security notes in the root README), so it's still
    // generated with real randomness rather than anything guessable.
    static std::string generate();
};