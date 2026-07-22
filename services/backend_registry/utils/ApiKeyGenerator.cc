#include "ApiKeyGenerator.h"
#include <random>
#include <sstream>
#include <iomanip>

std::string ApiKeyGenerator::generate() 
{
    // std::random_device is seeded from OS entropy - good enough for
    // generating an unguessable-in-practice key for this project.
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    // 32 hex characters = 128 bits of randomness, split across two 64-bit
    // random values because uniform_int_distribution<uint64_t> is the
    // widest single draw std::mt19937_64 comfortably supports.
    uint64_t part1 = dist(gen);
    uint64_t part2 = dist(gen);

    std::ostringstream oss;
    oss << "whk_live_"
        << std::hex << std::setfill('0')
        << std::setw(16) << part1
        << std::setw(16) << part2;

    return oss.str();
}