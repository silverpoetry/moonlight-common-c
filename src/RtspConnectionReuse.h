#pragma once

#include <stdbool.h>
#include <string.h>

#define RTSP_PERSISTENT_CONNECTION_HEADER "X-SS-Persistent-RTSP"

// Negotiate only with an authenticated, successful OPTIONS response. Servers
// without this exact opt-in retain the legacy one-request-per-socket behavior.
static inline bool rtspCanReuseConnection(bool encrypted, const char* command,
                                         int status, const char* version) {
    return encrypted && status == 200 && strcmp(command, "OPTIONS") == 0 &&
           version != NULL && strcmp(version, "1") == 0;
}
