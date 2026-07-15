#pragma once

#include <string>
#include <functional>
#include <drogon/drogon.h>

class UserRepository 
{
public:
    static void findByEmail(
        const std::string &email,
        std::function<void(int id, const std::string &passwordHash)> onFound,
        std::function<void()> onNotFound,
        std::function<void(const std::string &error)> onError
    );

    static void insert(
        const std::string &email,
        const std::string &passwordHash,
        std::function<void()> onSuccess,
        std::function<void()> onDuplicate,
        std::function<void(const std::string &error)> onError
    );
};