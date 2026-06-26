#include "SecurityService.h"
#include "../repositories/SecurityRepository.h"
#include <algorithm>
#include <regex>
#include <iostream>

// ============================================================
// Step 2 (Build Plan): SQL Injection Detector
// Scans input for known SQLi patterns such as:
//   ' OR 1=1 --
//   UNION SELECT
//   DROP TABLE
//   ; DELETE FROM
// Returns true if a SQLi pattern is detected.
// ============================================================
bool SecurityService::detectSQLi(const std::string& input) {
    // Convert input to lowercase for case-insensitive matching
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Known SQL injection patterns from the project spec
    std::vector<std::regex> patterns = {
        std::regex("('\\s*(or|and)\\s+.*=.*--)"),          // ' OR 1=1 --
        std::regex("(union\\s+(all\\s+)?select)"),          // UNION SELECT / UNION ALL SELECT
        std::regex("(drop\\s+table)"),                      // DROP TABLE
        std::regex("(;\\s*(delete|drop|insert|update)\\s)"),// ; DELETE FROM / ; DROP ...
        std::regex("('\\s*;\\s*--)"),                       // '; --
        std::regex("(\\b(select|insert|update|delete)\\b.*\\b(from|into|set)\\b)", std::regex::icase), // SELECT ... FROM
        std::regex("(1\\s*=\\s*1)"),                        // 1=1
        std::regex("('\\s*or\\s+'.*'\\s*=\\s*')"),          // ' or 'a'='a'
    };

    for (const auto& pattern : patterns) {
        if (std::regex_search(lower, pattern)) {
            return true;
        }
    }
    return false;
}

// ============================================================
// Step 3 (Build Plan): Cross-Site Scripting (XSS) Detector
// Scans input for script tags and dangerous event handlers like:
//   <script>alert(1)</script>
//   onload=...
// Returns true if an XSS pattern is detected.
// ============================================================
bool SecurityService::detectXSS(const std::string& input) {
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    std::vector<std::regex> patterns = {
        std::regex("(<\\s*script.*?>)"),                                // <script> tags
        std::regex("(javascript\\s*:)"),                                // javascript: URI
        std::regex("(on(load|error|click|mouseover|focus|blur)\\s*=)"), // Inline event handlers
        std::regex("(<\\s*iframe.*?>)"),                                // <iframe> tags
        std::regex("(<\\s*object.*?>)"),                                // <object> tags
    };

    for (const auto& pattern : patterns) {
        if (std::regex_search(lower, pattern)) {
            return true;
        }
    }
    return false;
}
