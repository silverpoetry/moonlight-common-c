#include "RtspConnectionReuse.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    assert(rtspCanReuseConnection(true, "OPTIONS", 200, "1"));
    assert(!rtspCanReuseConnection(false, "OPTIONS", 200, "1"));
    assert(!rtspCanReuseConnection(true, "OPTIONS", 200, NULL));
    assert(!rtspCanReuseConnection(true, "OPTIONS", 200, ""));
    assert(!rtspCanReuseConnection(true, "OPTIONS", 200, "2"));
    assert(!rtspCanReuseConnection(true, "OPTIONS", 200, "1x"));
    assert(!rtspCanReuseConnection(true, "OPTIONS", 403, "1"));
    assert(!rtspCanReuseConnection(true, "DESCRIBE", 200, "1"));
    puts("RTSP connection reuse negotiation: PASSED");
    return 0;
}
