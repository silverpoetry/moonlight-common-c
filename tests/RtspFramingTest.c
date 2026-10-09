#include "RtspFraming.h"

#include <stdio.h>
#include <string.h>

static int expect(const char* name, int actual, int expected) {
    if (actual == expected) return 0;
    fprintf(stderr, "%s: got %d, expected %d\n", name, actual, expected);
    return 1;
}

int main(void) {
    char frame[64] = {0};
    int failures = 0;
    frame[0] = (char)0x80;
    frame[3] = 8;

    // All TCP split points must stay pending until both the tag and ciphertext
    // are present. A complete response is accepted without a subsequent EOF.
    for (size_t length = 0; length < 32; length++) {
        failures += expect("fragmented response", rtspEncryptedFrameStatus(frame, length, 1024), 0);
    }
    failures += expect("complete without EOF", rtspEncryptedFrameStatus(frame, 32, 1024), 1);
    failures += expect("excess bytes", rtspEncryptedFrameStatus(frame, 33, 1024), -1);
    failures += expect("maximum exact fit", rtspEncryptedFrameStatus(frame, 32, 32), 1);
    failures += expect("oversized frame", rtspEncryptedFrameStatus(frame, 24, 31), -1);
    failures += expect("maximum below header", rtspEncryptedFrameStatus(frame, 24, 23), -1);
    frame[0] = 0;
    failures += expect("unencrypted downgrade", rtspEncryptedFrameStatus(frame, 32, 1024), -1);
    frame[0] = (char)0x80;
    frame[3] = 0;
    failures += expect("empty payload", rtspEncryptedFrameStatus(frame, 24, 1024), -1);
    memset(frame, 0xff, 4);
    failures += expect("hostile length", rtspEncryptedFrameStatus(frame, 24, 1024), -1);

    printf("RTSP framing: %s\n", failures ? "FAILED" : "PASSED");
    return failures != 0;
}
