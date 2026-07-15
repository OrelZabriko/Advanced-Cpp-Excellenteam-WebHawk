#pragma once

#include <cstdlib>
#include <string>
#include <fstream>

// Shared .env parsing used by DbConfig, AuthConfig, and SecurityConfig.
// Safe to call from all three - the file is only actually read once per
// process, no matter how many of them call ensureLoaded().
class EnvLoader 
{
public:
    static void ensureLoaded() 
    {
        static bool loaded = load();
        (void)loaded;
    }

private:
    static bool load() 
    {
        // The binary runs with its working directory set to services/<name>/,
        // but there's a single .env at the repo root, two levels up.
        std::ifstream file(".env");
        if (!file.is_open()) file.open("../../.env");
        if (!file.is_open()) file.open("../.env");
        if (!file.is_open()) return false;

        std::string line;
        while (std::getline(file, line)) 
        {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line[0] == '#') continue;
            auto pos = line.find('=');
            if (pos == std::string::npos) continue;
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            setenv(key.c_str(), value.c_str(), 1);
        }
        return true;
    }
};