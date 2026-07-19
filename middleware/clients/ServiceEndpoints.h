#pragma once

#include <string>

// The internal Docker-network addresses of the other three services.
// These work because Docker Compose's internal DNS resolves each service
// name (e.g. "users") to that container's address - see the root README's
// explanation of why this is "users"/"security-engine"/"backend-registry"
// and never "localhost" from inside this container.
//
// Not read from .env on purpose: these are structural/topological facts
// about how the services are wired together in docker-compose.yml, not
// secrets or per-environment settings - unlike DB credentials, they don't
// need to change between people's machines.
namespace ServiceEndpoints 
{
    inline const std::string USERS = "http://users:8080";
    inline const std::string SECURITY_ENGINE = "http://security_engine:8080";
    inline const std::string BACKEND_REGISTRY = "http://backend_registry:8080";
}