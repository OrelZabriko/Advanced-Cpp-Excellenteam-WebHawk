#include <drogon/drogon.h>
#include "../shared/DbConfig.h"
#include "../shared/ErrorHandlers.h"

int main() 
{
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