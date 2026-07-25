#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LI_CLIPBOARD_PTYPE 0x3001

#define LI_CLIPBOARD_VERSION_V1 1
#define LI_CLIPBOARD_VERSION_V2 2

#define LI_CLIPBOARD_V1_HEADER_SIZE 20
#define LI_CLIPBOARD_V2_HEADER_SIZE 36

#define LI_CLIPBOARD_MAX_TEXT_BYTES (1024U * 1024U)
#define LI_CLIPBOARD_MAX_PNG_INLINE_BYTES (1024U * 1024U)
#define LI_CLIPBOARD_MAX_BLOB_REFERENCE_BYTES 128U
#define LI_CLIPBOARD_MAX_CHUNK_BYTES (16U * 1024U)
#define LI_CLIPBOARD_MAX_IMAGE_PIXELS (32U * 1024U * 1024U)

#define LI_CLIPBOARD_OP_HELLO 0x01
#define LI_CLIPBOARD_OP_ANNOUNCE 0x02
#define LI_CLIPBOARD_OP_REQUEST 0x03
#define LI_CLIPBOARD_OP_DATA 0x04
#define LI_CLIPBOARD_OP_ACK 0x05
#define LI_CLIPBOARD_OP_NACK 0x06
#define LI_CLIPBOARD_OP_RELEASE 0x07

#define LI_CLIPBOARD_MIME_NONE 0x00
#define LI_CLIPBOARD_MIME_TEXT_UTF8 0x01
#define LI_CLIPBOARD_MIME_PNG 0x02
#define LI_CLIPBOARD_MIME_BLOB_REFERENCE 0x03

#define LI_CLIPBOARD_CAP_CAN_SEND 0x01
#define LI_CLIPBOARD_CAP_CAN_RECEIVE 0x02
#define LI_CLIPBOARD_CAP_TEXT 0x04
#define LI_CLIPBOARD_CAP_PNG 0x08
#define LI_CLIPBOARD_CAP_BLOB 0x10

#define LI_CLIPBOARD_BLOB_REFERENCE_VERSION 1
#define LI_CLIPBOARD_BLOB_REFERENCE_HEADER_SIZE 40
#define LI_CLIPBOARD_BLOB_ID_MAX_BYTES 64
#define LI_CLIPBOARD_SHA256_BYTES 32

typedef struct _LI_CLIPBOARD_V2_HEADER {
    uint8_t version;
    uint8_t op;
    uint8_t mimeType;
    uint8_t flags;
    uint32_t sequence;
    uint64_t originId;
    uint64_t itemId;
    uint32_t totalLength;
    uint32_t chunkOffset;
    uint32_t chunkLength;
} LI_CLIPBOARD_V2_HEADER, *PLI_CLIPBOARD_V2_HEADER;

typedef struct _LI_CLIPBOARD_BLOB_REFERENCE {
    uint8_t targetMimeType;
    uint32_t size;
    uint8_t sha256[LI_CLIPBOARD_SHA256_BYTES];
    uint8_t idLength;
    char id[LI_CLIPBOARD_BLOB_ID_MAX_BYTES + 1];
} LI_CLIPBOARD_BLOB_REFERENCE, *PLI_CLIPBOARD_BLOB_REFERENCE;

bool LiEncodeClipboardV2Header(uint8_t* destination,
                               size_t destinationLength,
                               const LI_CLIPBOARD_V2_HEADER* header);

bool LiDecodeClipboardV2Header(const uint8_t* source,
                               size_t sourceLength,
                               PLI_CLIPBOARD_V2_HEADER header);

bool LiEncodeClipboardBlobReference(uint8_t* destination,
                                    size_t destinationLength,
                                    const LI_CLIPBOARD_BLOB_REFERENCE* reference,
                                    size_t* encodedLength);

bool LiDecodeClipboardBlobReference(const uint8_t* source,
                                    size_t sourceLength,
                                    PLI_CLIPBOARD_BLOB_REFERENCE reference);

bool LiIsClipboardMimeSupported(uint8_t mimeType, uint8_t capabilities);
uint32_t LiGetClipboardMimeSizeLimit(uint8_t mimeType);
bool LiIsValidUtf8ClipboardText(const uint8_t* text, size_t length);
bool LiIsValidClipboardPngHeader(const uint8_t* png, size_t length);

#ifdef __cplusplus
}
#endif
