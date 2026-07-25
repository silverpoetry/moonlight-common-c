#include <Srtp.h>

#include <stdio.h>
#include <string.h>

static int expectBytes(const char* name, const uint8_t* actual,
                       const uint8_t* expected, size_t length) {
    if (memcmp(actual, expected, length) == 0) {
        return 0;
    }

    fprintf(stderr, "%s mismatch\n", name);
    return 1;
}

int main(void) {
    static const uint8_t expectedRtpKey[16] = {
        0x8A, 0x27, 0x6C, 0x1F, 0x8D, 0x38, 0x9C, 0x34,
        0x2B, 0x92, 0xB6, 0x8D, 0x3D, 0x62, 0xE9, 0x78,
    };
    static const uint8_t expectedRtpSalt[12] = {
        0x97, 0x03, 0xF8, 0x24, 0x6E, 0x40,
        0xF9, 0x79, 0xB0, 0xD6, 0xD0, 0x16,
    };
    static const uint8_t expectedRtcpKey[16] = {
        0x02, 0xB7, 0xCB, 0x2C, 0xAE, 0xFA, 0xDA, 0x3A,
        0x4E, 0x4E, 0x07, 0x1F, 0x64, 0xBB, 0xEB, 0x04,
    };
    static const uint8_t expectedRtcpSalt[12] = {
        0x62, 0x0B, 0x8B, 0xCE, 0xD9, 0x69,
        0x9B, 0xED, 0x3A, 0xB4, 0x79, 0x09,
    };
    static const uint8_t rfc7714Salt[12] = {
        0x51, 0x75, 0x69, 0x64, 0x20, 0x70,
        0x72, 0x6F, 0x20, 0x71, 0x75, 0x6F,
    };
    static const uint8_t rfc7714Iv[12] = {
        0x51, 0x75, 0x3C, 0x65, 0x80, 0xC2,
        0x72, 0x6F, 0x20, 0x71, 0x84, 0x14,
    };
    uint8_t inputKey[16];
    uint8_t inputIv[16];
    const uint8_t pingPayload[16] = "0123456789ABCDEF";
    SRTP_SESSION_KEYS keys;
    uint8_t iv[12];
    int failures = 0;

    for (int i = 0; i < 16; i++) {
        inputKey[i] = (uint8_t)i;
        inputIv[i] = (uint8_t)(0xF0 + i);
    }

    if (!SrtpDeriveSessionKeys(inputKey, inputIv, pingPayload, &keys)) {
        fprintf(stderr, "SrtpDeriveSessionKeys failed\n");
        return 1;
    }

    failures += expectBytes("RTP key", keys.rtpKey,
                            expectedRtpKey, sizeof(expectedRtpKey));
    failures += expectBytes("RTP salt", keys.rtpSalt,
                            expectedRtpSalt, sizeof(expectedRtpSalt));
    failures += expectBytes("RTCP key", keys.rtcpKey,
                            expectedRtcpKey, sizeof(expectedRtcpKey));
    failures += expectBytes("RTCP salt", keys.rtcpSalt,
                            expectedRtcpSalt, sizeof(expectedRtcpSalt));

    SrtpCreateRtpAeadIv(rfc7714Salt, 0x5501A0B2, 0, 0xF17B, iv);
    failures += expectBytes("RFC 7714 RTP IV", iv,
                            rfc7714Iv, sizeof(rfc7714Iv));
    return failures == 0 ? 0 : 1;
}
