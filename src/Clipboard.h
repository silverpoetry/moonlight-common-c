#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LI_CLIPBOARD_PTYPE 0x3001

#define LI_CLIPBOARD_VERSION 4
#define LI_CLIPBOARD_HEADER_SIZE 36

#define LI_CLIPBOARD_MAX_TEXT_BYTES (1024U * 1024U)
#define LI_CLIPBOARD_MAX_PNG_INLINE_BYTES (1024U * 1024U)
#define LI_CLIPBOARD_MAX_BLOB_REFERENCE_BYTES 128U
#define LI_CLIPBOARD_MAX_FILE_OFFER_BYTES 72U
#define LI_CLIPBOARD_MAX_CHUNK_BYTES (16U * 1024U)
#define LI_CLIPBOARD_MAX_IMAGE_PIXELS (32U * 1024U * 1024U)
#define LI_CLIPBOARD_MAX_FILE_MANIFEST_BYTES (1024U * 1024U)
#define LI_CLIPBOARD_MAX_FILE_ENTRIES 4096U
#define LI_CLIPBOARD_MAX_FILE_PATH_BYTES 1024U
#define LI_CLIPBOARD_MAX_FILE_CHUNK_BYTES (4U * 1024U * 1024U)
#define LI_CLIPBOARD_MAX_FILE_BYTES (UINT64_C(64) * 1024U * 1024U * 1024U)
#define LI_CLIPBOARD_MAX_FILE_TRANSFER_BYTES (UINT64_C(256) * 1024U * 1024U * 1024U)

#define LI_CLIPBOARD_OP_HELLO 0x01
#define LI_CLIPBOARD_OP_ANNOUNCE 0x02
#define LI_CLIPBOARD_OP_REQUEST 0x03
#define LI_CLIPBOARD_OP_DATA 0x04
#define LI_CLIPBOARD_OP_ACK 0x05
#define LI_CLIPBOARD_OP_NACK 0x06
#define LI_CLIPBOARD_OP_RELEASE 0x07

#define LI_CLIPBOARD_NACK_INVALID_DATA 0x01
#define LI_CLIPBOARD_NACK_UNSUPPORTED 0x02
#define LI_CLIPBOARD_NACK_SOURCE_UNAVAILABLE 0x03
#define LI_CLIPBOARD_NACK_BUSY 0x04
#define LI_CLIPBOARD_NACK_TEMPORARY 0x05
#define LI_CLIPBOARD_NACK_CANCELLED 0x06

#define LI_CLIPBOARD_MIME_NONE 0x00
#define LI_CLIPBOARD_MIME_TEXT_UTF8 0x01
#define LI_CLIPBOARD_MIME_PNG 0x02
#define LI_CLIPBOARD_MIME_BLOB_REFERENCE 0x03
#define LI_CLIPBOARD_MIME_FILE_OFFER 0x05

#define LI_CLIPBOARD_CAP_CAN_SEND 0x01
#define LI_CLIPBOARD_CAP_CAN_RECEIVE 0x02
#define LI_CLIPBOARD_CAP_TEXT 0x04
#define LI_CLIPBOARD_CAP_PNG 0x08
#define LI_CLIPBOARD_CAP_BLOB 0x10
#define LI_CLIPBOARD_CAP_FILES 0x20
#define LI_CLIPBOARD_CAP_FILE_STREAMS 0x40
#define LI_CLIPBOARD_KNOWN_CAPABILITIES \
    (LI_CLIPBOARD_CAP_CAN_SEND | LI_CLIPBOARD_CAP_CAN_RECEIVE | \
     LI_CLIPBOARD_CAP_TEXT | LI_CLIPBOARD_CAP_PNG | \
     LI_CLIPBOARD_CAP_BLOB | LI_CLIPBOARD_CAP_FILES | \
     LI_CLIPBOARD_CAP_FILE_STREAMS)

#define LI_CLIPBOARD_BLOB_REFERENCE_VERSION 1
#define LI_CLIPBOARD_BLOB_REFERENCE_HEADER_SIZE 40
#define LI_CLIPBOARD_BLOB_ID_MAX_BYTES 64
#define LI_CLIPBOARD_SHA256_BYTES 32

#define LI_CLIPBOARD_FILE_OFFER_VERSION 1
#define LI_CLIPBOARD_FILE_OFFER_HEADER_SIZE 8
#define LI_CLIPBOARD_FILE_OFFER_ID_MAX_BYTES 64

#define LI_CLIPBOARD_FILE_MANIFEST_VERSION 1
#define LI_CLIPBOARD_FILE_MANIFEST_HEADER_SIZE 24
#define LI_CLIPBOARD_FILE_MANIFEST_ENTRY_HEADER_SIZE 24
#define LI_CLIPBOARD_FILE_TYPE_REGULAR 1
#define LI_CLIPBOARD_FILE_TYPE_DIRECTORY 2

typedef struct _LI_CLIPBOARD_HEADER {
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
} LI_CLIPBOARD_HEADER, *PLI_CLIPBOARD_HEADER;

typedef struct _LI_CLIPBOARD_BLOB_REFERENCE {
    uint8_t targetMimeType;
    uint32_t size;
    uint8_t sha256[LI_CLIPBOARD_SHA256_BYTES];
    uint8_t idLength;
    char id[LI_CLIPBOARD_BLOB_ID_MAX_BYTES + 1];
} LI_CLIPBOARD_BLOB_REFERENCE, *PLI_CLIPBOARD_BLOB_REFERENCE;

typedef struct _LI_CLIPBOARD_FILE_OFFER {
    uint8_t idLength;
    char id[LI_CLIPBOARD_FILE_OFFER_ID_MAX_BYTES + 1];
} LI_CLIPBOARD_FILE_OFFER, *PLI_CLIPBOARD_FILE_OFFER;

typedef struct _LI_CLIPBOARD_FILE_MANIFEST_HEADER {
    uint32_t entryCount;
    uint32_t fileCount;
    uint64_t totalFileBytes;
} LI_CLIPBOARD_FILE_MANIFEST_HEADER, *PLI_CLIPBOARD_FILE_MANIFEST_HEADER;

typedef struct _LI_CLIPBOARD_FILE_MANIFEST_ENTRY {
    uint8_t type;
    uint32_t pathLength;
    uint64_t size;
    uint64_t modifiedTimeMs;
    const uint8_t* path;
} LI_CLIPBOARD_FILE_MANIFEST_ENTRY, *PLI_CLIPBOARD_FILE_MANIFEST_ENTRY;

bool LiEncodeClipboardHeader(uint8_t* destination,
                             size_t destinationLength,
                             const LI_CLIPBOARD_HEADER* header);

bool LiDecodeClipboardHeader(const uint8_t* source,
                             size_t sourceLength,
                             PLI_CLIPBOARD_HEADER header);

// Validates the direction and format capability contract exchanged by HELLO.
// File streaming is an atomic capability pair and blob transport is only
// meaningful when at least one blob-backed MIME type is also supported.
bool LiIsValidClipboardCapabilities(uint8_t capabilities);

// Validates the operation-specific wire invariants of a decoded clipboard
// message, including the complete payload length. Connection state and peer
// capability checks remain the caller's responsibility.
bool LiIsValidClipboardMessage(const LI_CLIPBOARD_HEADER* header,
                               size_t payloadLength);

bool LiIsValidClipboardNackReason(uint8_t reason);
bool LiIsClipboardNackRetryable(uint8_t reason);

bool LiEncodeClipboardBlobReference(uint8_t* destination,
                                    size_t destinationLength,
                                    const LI_CLIPBOARD_BLOB_REFERENCE* reference,
                                    size_t* encodedLength);

bool LiDecodeClipboardBlobReference(const uint8_t* source,
                                    size_t sourceLength,
                                    PLI_CLIPBOARD_BLOB_REFERENCE reference);

bool LiEncodeClipboardFileOffer(uint8_t* destination,
                                size_t destinationLength,
                                const LI_CLIPBOARD_FILE_OFFER* offer,
                                size_t* encodedLength);

bool LiDecodeClipboardFileOffer(const uint8_t* source,
                                size_t sourceLength,
                                PLI_CLIPBOARD_FILE_OFFER offer);

bool LiEncodeClipboardFileManifestHeader(uint8_t* destination,
                                         size_t destinationLength,
                                         const LI_CLIPBOARD_FILE_MANIFEST_HEADER* header);

bool LiDecodeClipboardFileManifestHeader(const uint8_t* source,
                                         size_t sourceLength,
                                         PLI_CLIPBOARD_FILE_MANIFEST_HEADER header);

bool LiEncodeClipboardFileManifestEntry(uint8_t* destination,
                                        size_t destinationLength,
                                        const LI_CLIPBOARD_FILE_MANIFEST_ENTRY* entry,
                                        size_t* encodedLength);

bool LiDecodeClipboardFileManifestEntry(const uint8_t* source,
                                        size_t sourceLength,
                                        size_t* offset,
                                        PLI_CLIPBOARD_FILE_MANIFEST_ENTRY entry);

bool LiIsValidClipboardFileManifest(const uint8_t* manifest, size_t length);

bool LiIsClipboardMimeSupported(uint8_t mimeType, uint8_t capabilities);
uint32_t LiGetClipboardMimeSizeLimit(uint8_t mimeType);
bool LiIsValidUtf8ClipboardText(const uint8_t* text, size_t length);
bool LiIsValidClipboardPngHeader(const uint8_t* png, size_t length);

#ifdef __cplusplus
}
#endif
