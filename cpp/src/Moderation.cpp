#include "Moderation.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace moderation {
namespace {

std::string toLower(const std::string& in) {
    std::string out(in.size(), '\0');
    std::transform(in.begin(), in.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// A copy with all whitespace removed, so patterns that authors split across
// spaces/newlines (e.g. "window . open (") still match.
std::string stripWhitespace(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        if (std::isspace(c) == 0) {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

bool isWordChar(unsigned char c) {
    return std::isalnum(c) != 0 || c == '_';
}

// Whole-word, case-insensitive match. `word` must already be lowercase and is
// matched against `lowerHaystack`. Used for adult terms so that, e.g., "sextet"
// does not trip a match for "sex".
bool containsWord(const std::string& lowerHaystack, const std::string& word) {
    size_t pos = 0;
    while ((pos = lowerHaystack.find(word, pos)) != std::string::npos) {
        bool leftOk = (pos == 0) ||
                      !isWordChar(static_cast<unsigned char>(lowerHaystack[pos - 1]));
        size_t end = pos + word.size();
        bool rightOk = (end >= lowerHaystack.size()) ||
                       !isWordChar(static_cast<unsigned char>(lowerHaystack[end]));
        if (leftOk && rightOk) {
            return true;
        }
        pos = end;
    }
    return false;
}

size_t countOccurrences(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) {
        return 0;
    }
    size_t count = 0;
    size_t pos = 0;
    while ((pos = haystack.find(needle, pos)) != std::string::npos) {
        ++count;
        pos += needle.size();
    }
    return count;
}

// True if `lhs` appears in `compact` immediately followed by a single '='
// assignment (as opposed to "==" / "===" comparison or "=>" arrow). `compact`
// is expected to be whitespace-stripped and lowercase.
bool containsAssignment(const std::string& compact, const std::string& lhs) {
    size_t pos = 0;
    while ((pos = compact.find(lhs, pos)) != std::string::npos) {
        size_t after = pos + lhs.size();
        if (after < compact.size() && compact[after] == '=') {
            char next = (after + 1 < compact.size()) ? compact[after + 1] : '\0';
            if (next != '=' && next != '>') {
                return true;
            }
        }
        pos = after;
    }
    return false;
}

ModerationResult clean() {
    return ModerationResult{true, "clean", "", ""};
}

ModerationResult block(const std::string& category, const std::string& reason,
                       const std::string& match) {
    return ModerationResult{false, category, reason, match};
}

// ---- Redirect detection ------------------------------------------------------

ModerationResult checkRedirects(const std::string& compact) {
    // <meta http-equiv="refresh" content="0;url=..."> style auto-redirects.
    const char* metaRefreshForms[] = {
        "http-equiv=\"refresh\"",
        "http-equiv='refresh'",
        "http-equiv=refresh",
    };
    for (const char* form : metaRefreshForms) {
        if (compact.find(form) != std::string::npos && compact.find("url=") != std::string::npos) {
            return block("redirect", "meta-refresh auto-redirect to another URL", "meta refresh");
        }
    }

    // JavaScript navigation calls always redirect.
    if (compact.find("location.replace(") != std::string::npos) {
        return block("redirect", "script redirect via location.replace()", "location.replace(");
    }
    if (compact.find("location.assign(") != std::string::npos) {
        return block("redirect", "script redirect via location.assign()", "location.assign(");
    }

    // Assignments to a location property: window.location = ..., location.href = ...
    if (containsAssignment(compact, "location.href")) {
        return block("redirect", "script redirect via location.href assignment", "location.href=");
    }
    if (containsAssignment(compact, ".location")) {
        return block("redirect", "script redirect via location assignment", ".location=");
    }

    return clean();
}

// ---- Popup / dialog abuse detection -----------------------------------------

ModerationResult checkPopups(const std::string& compact) {
    const bool hasLoop = compact.find("for(") != std::string::npos ||
                         compact.find("while(") != std::string::npos ||
                         compact.find("setinterval(") != std::string::npos;

    const size_t opens = countOccurrences(compact, "window.open(");
    if (opens > 0 && (hasLoop || opens >= 2)) {
        return block("popup", "repeated or looped window.open() popups", "window.open(");
    }

    // Unload traps: onbeforeunload / beforeunload handlers keep visitors stuck
    // or re-spawn windows when they try to leave.
    if (compact.find("beforeunload") != std::string::npos) {
        return block("popup", "traps navigation with a beforeunload handler", "beforeunload");
    }

    // Dialog bombs: alert/confirm/prompt driven from a loop or timer.
    if (hasLoop && (compact.find("alert(") != std::string::npos ||
                    compact.find("confirm(") != std::string::npos ||
                    compact.find("prompt(") != std::string::npos)) {
        return block("popup", "looped alert()/confirm()/prompt() dialog spam", "dialog loop");
    }

    return clean();
}

// ---- Adult content detection -------------------------------------------------

ModerationResult checkAdult(const std::string& lower) {
    // Whole-word matched, unambiguous explicit terms.
    static const char* kAdultTerms[] = {
        "porn", "pornography", "pornhub", "xvideos", "xnxx", "xhamster",
        "redtube", "youporn", "onlyfans", "nsfw", "hardcore porn",
        "sex tape", "sex cam", "sex chat", "camgirl", "camgirls",
        "escort service", "escorts", "hentai", "rule34", "blowjob",
        "cumshot", "creampie", "deepthroat", "masturbation", "fleshlight",
        "dildo", "milf", "gangbang", "bukkake", "asa", "valentina"
    };
    for (const char* term : kAdultTerms) {
        if (containsWord(lower, term)) {
            return block("adult", "sexually explicit content", term);
        }
    }
    return clean();
}

}  // namespace

ModerationResult moderateHtml(const std::string& content) {
    const std::string lower = toLower(content);
    const std::string compact = stripWhitespace(lower);

    if (ModerationResult r = checkRedirects(compact); r.blocked()) {
        return r;
    }
    if (ModerationResult r = checkPopups(compact); r.blocked()) {
        return r;
    }
    if (ModerationResult r = checkAdult(lower); r.blocked()) {
        return r;
    }
    return clean();
}

std::string blockedNoticePage(const ModerationResult& result) {
    // Escape the reason before embedding it in the notice.
    std::string safeReason;
    safeReason.reserve(result.reason.size());
    for (char c : result.reason) {
        switch (c) {
            case '&': safeReason += "&amp;"; break;
            case '<': safeReason += "&lt;"; break;
            case '>': safeReason += "&gt;"; break;
            case '"': safeReason += "&quot;"; break;
            default: safeReason += c; break;
        }
    }

    return std::string(R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Content Blocked</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
            color: #333;
        }
        .card {
            background: #fff;
            border: 1px solid #f5c2c7;
            border-radius: 12px;
            padding: 32px 40px;
            max-width: 480px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        h1 { color: #842029; margin-top: 0; }
        code {
            background: #fff5f5;
            padding: 2px 6px;
            border-radius: 4px;
            color: #842029;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>&#128683; Content Blocked</h1>
        <p>This static override was blocked by content moderation.</p>
        <p>Reason: <code>)") + safeReason + R"(</code></p>
    </div>
</body>
</html>)";
}

}  // namespace moderation
