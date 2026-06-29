#pragma once
#include <cstdlib>
#include <string>
#include <fstream>

class Config {
private:
    static void load() {
        std::ifstream file(".env");
        if (!file.is_open()) return;
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto pos = line.find('=');
            if (pos == std::string::npos) continue;
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            setenv(key.c_str(), value.c_str(), 1);
        }
    }

    // Called once automatically when Config is first used
    static bool init() {
        load();
        return true;
    }

    static inline bool _initialized = init();

public:
    static std::string JWT_SECRET() {
        const char* val = std::getenv("JWT_SECRET");
        return val ? std::string(val) : "default_secret";
    }

    static std::string JWT_ALGORITHM() {
        const char* val = std::getenv("JWT_ALGORITHM");
        return val ? std::string(val) : "HS256";
    }

    static int JWT_EXPIRY_SECS() {
        const char* val = std::getenv("JWT_EXPIRY_SECS");
        return val ? std::stoi(val) : 86400;
    }

    static int RATE_LIMIT_MAX_REQUESTS() {
        const char* val = std::getenv("RATE_LIMIT_MAX_REQUESTS");
        return val ? std::stoi(val) : 100;
    }

    static int RATE_LIMIT_WINDOW_SECS() {
        const char* val = std::getenv("RATE_LIMIT_WINDOW_SECS");
        return val ? std::stoi(val) : 60;
    }
};