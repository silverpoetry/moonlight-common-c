#pragma once

#include <stddef.h>
#include <stdint.h>

#define RTSP_ENCRYPTED_HEADER_SIZE 24

// Returns 1 for one complete encrypted frame, 0 for a partial frame, and -1
// for invalid framing. Authentication and RTSP parsing still follow receipt.
static inline int rtspEncryptedFrameStatus(const char* data, size_t length, size_t maximumSize) {
    uint32_t typeAndLength;
    size_t payloadLength;
    size_t frameLength;

    if (length < RTSP_ENCRYPTED_HEADER_SIZE) {
        return 0;
    }

    typeAndLength = ((uint32_t)(uint8_t)data[0] << 24) |
                    ((uint32_t)(uint8_t)data[1] << 16) |
                    ((uint32_t)(uint8_t)data[2] << 8) |
                    (uint32_t)(uint8_t)data[3];
    payloadLength = typeAndLength & UINT32_C(0x7fffffff);
    if (!(typeAndLength & UINT32_C(0x80000000)) || payloadLength == 0 ||
            maximumSize < RTSP_ENCRYPTED_HEADER_SIZE ||
            payloadLength > maximumSize - RTSP_ENCRYPTED_HEADER_SIZE) {
        return -1;
    }

    frameLength = RTSP_ENCRYPTED_HEADER_SIZE + payloadLength;
    return length > frameLength ? -1 : length == frameLength ? 1 : 0;
}
