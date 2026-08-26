#pragma once

#include <string>

// Lightweight, dependency-free content moderation for static-override websites.
//
// The static-override feature lets anyone with editor access host arbitrary HTML
// through the DNS server. In practice the abuse we care about is not binary
// malware but hostile *page behavior* and inappropriate material:
//
//   * popup bombs   - loops of window.open(), alert/confirm/prompt spam, and
//                     onbeforeunload traps that stop a visitor from leaving.
//   * auto redirect - <meta http-equiv="refresh"> and location assignments that
//                     instantly bounce the visitor to another site.
//   * adult content - sexually explicit material.
//
// moderateHtml() scans content for these so it can be rejected before it is
// written to disk and again before it is served to visitors.
namespace moderation {

struct ModerationResult {
    bool allowed = true;
    std::string category;  // "clean", "popup", "redirect", or "adult"
    std::string reason;    // human-readable explanation, empty when allowed
    std::string match;     // the offending token/signature, for logging

    bool blocked() const { return !allowed; }
};

// Scan HTML (or any text) content for abusive behavior and inappropriate
// material. Returns an allowed result with category "clean" when nothing is
// flagged.
ModerationResult moderateHtml(const std::string& content);

// A small HTML notice served in place of content that failed moderation.
std::string blockedNoticePage(const ModerationResult& result);

}  // namespace moderation
