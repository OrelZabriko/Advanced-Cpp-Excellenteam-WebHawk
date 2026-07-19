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
        std::ifstream file(".env");
        if (!file.is_open()) file.open("../../.env");
        if (!file.is_open()) file.open("../.env");
        if (!file.is_open()) return false;

        auto trim = [](std::string s) {
            size_t start = s.find_first_not_of(" \t");
            if (start == std::string::npos) return std::string();
            size_t end = s.find_last_not_of(" \t");
            return s.substr(start, end - start + 1);
        };

        std::string line;
        while (std::getline(file, line)) 
        {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            line = trim(line);
            if (line.empty() || line[0] == '#') continue;
            auto pos = line.find('=');
            if (pos == std::string::npos) continue;
            std::string key = trim(line.substr(0, pos));
            std::string value = trim(line.substr(pos + 1));
            setenv(key.c_str(), value.c_str(), 1);
        }
        return true;
    }
};