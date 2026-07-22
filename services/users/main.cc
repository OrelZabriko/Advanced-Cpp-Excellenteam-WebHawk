#include <drogon/drogon.h>
#include "../shared/DbConfig.h"
#include "utils/AuthConfig.h"
#include "../shared/ErrorHandlers.h"
#include <iostream>
#include <cstdlib>

int main() 
{
    try
    {
        // Fails fast, before the server starts listening, if JWT_SECRET or
        // JWT_ALGORITHM is invalid - see AuthConfig::JWT_SECRET() and
        // AuthConfig::algorithmEnum(). Caught below instead of letting it
        // reach std::terminate(), so the failure reason is a single clear
        // line instead of a raw "terminate called..." dump.
        AuthConfig::JWT_SECRET();
        AuthConfig::algorithmEnum();

        // The DB client is built here in code - rather than in config.json -
        // so the DB password never sits in a plain-text file that gets
        // committed to git. Values all come from the repo-root .env
        // (see services/shared/DbConfig.h).
        drogon::app().createDbClient(
            "postgresql",
            DbConfig::HOST(),
            DbConfig::PORT(),
            DbConfig::NAME(),
            DbConfig::USER(),
            DbConfig::PASSWORD(),
            4,          // connection pool size - 1 would serialize every async query in this service behind a single connection
            "",         // filename - unused for postgresql, only relevant for sqlite3
            "default",  // client name - must match what DB_Repository looks up via getDbClient("default")
            false       // isFast - Drogon's "fast" mode requires special handling; not used here
        );

        // Only port/listener settings remain in config.json - no credentials.
        drogon::app().loadConfigFile("config.json");

        // Guarantees every response from this service carries a JSON body -
        // including the 404/405 Drogon raises before routing, and any exception a
        // controller did not anticipate. Per-controller validation still handles
        // known bad input; this is the net underneath it.
        ErrorHandlers::installAll();

        drogon::app().run();
    }
    catch(const std::exception& e)
    {
        std::cerr << "[users] fatal startup error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
