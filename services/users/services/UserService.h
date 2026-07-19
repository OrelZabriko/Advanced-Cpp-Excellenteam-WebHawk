#pragma once

#include <string>
#include <functional>

class UserService 
{
    public:
        // Register a new user
        static void registerUser(
            const std::string &email,
            const std::string &password,
            std::function<void()> onSuccess,
            std::function<void()> onDuplicate,
            std::function<void(const std::string &error)> onError
        );
    
        // Login a user - returns JWT token on success
        static void loginUser(
            const std::string &email,
            const std::string &password,
            const std::string &ip,
            std::function<void(const std::string &token)> onSuccess,
            std::function<void()> onInvalidCredentials,
            std::function<void(const std::string &error)> onError
        );
    
        // Logout a user - revokes the session
        static void logoutUser(
            const std::string &tokenId,
            std::function<void()> onSuccess,
            std::function<void()> onNotFound,
            std::function<void(const std::string &error)> onError
        );
    
        // validates a JWT token
        static void validateToken(
            const std::string &token,
            std::function<void(int userId)> onValid,
            std::function<void(const std::string &reason)> onInvalid,
            std::function<void(const std::string &error)> onError
        );
};