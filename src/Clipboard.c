#include "Clipboard.h"

#include <string.h>

static uint32_t readLe32(const uint8_t* source) {
    return ((uint32_t)source[0]) |
           ((uint32_t)source[1] << 8) |
           ((uint32_t)source[2] << 16) |
           ((uint32_t)source[3] << 24);
}

static uint64_t readLe64(const uint8_t* source) {
    return ((uint64_t)readLe32(source)) |
           ((uint64_t)readLe32(source + 4) << 32);
}

static uint32_t readBe32(const uint8_t* source) {
    return ((uint32_t)source[0] << 24) |
           ((uint32_t)source[1] << 16) |
           ((uint32_t)source[2] << 8) |
           ((uint32_t)source[3]);
}

static void writeLe32(uint8_t* destination, uint32_t value) {
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8);
    destination[2] = (uint8_t)(value >> 16);
    destination[3] = (uint8_t)(value >> 24);
}

static void writeLe64(uint8_t* destination, uint64_t value) {
    writeLe32(destination, (uint32_t)value);
    writeLe32(destination + 4, (uint32_t)(value >> 32));
}

bool LiEncodeClipboardV2Header(uint8_t* destination,
                               size_t destinationLength,
                               const LI_CLIPBOARD_V2_HEADER* header) {
    if (destination == NULL || header == NULL || destinationLength < LI_CLIPBOARD_V2_HEADER_SIZE) {
        return false;
    }

    destination[0] = header->version;
    destination[1] = header->op;
    destination[2] = header->mimeType;
    destination[3] = header->flags;
    writeLe32(destination + 4, header->sequence);
    writeLe64(destination + 8, header->originId);
    writeLe64(destination + 16, header->itemId);
    writeLe32(destination + 24, header->totalLength);
    writeLe32(destination + 28, header->chunkOffset);
    writeLe32(destination + 32, header->chunkLength);
    return true;
}

bool LiDecodeClipboardV2Header(const uint8_t* source,
                               size_t sourceLength,
                               PLI_CLIPBOARD_V2_HEADER header) {
    if (source == NULL || header == NULL || sourceLength < LI_CLIPBOARD_V2_HEADER_SIZE) {
        return false;
    }

    header->version = source[0];
    header->op = source[1];
    header->mimeType = source[2];
    header->flags = source[3];
    header->sequence = readLe32(source + 4);
    header->originId = readLe64(source + 8);
    header->itemId = readLe64(source + 16);
    header->totalLength = readLe32(source + 24);
    header->chunkOffset = readLe32(source + 28);
    header->chunkLength = readLe32(source + 32);
    return true;
}

bool LiEncodeClipboardBlobReference(uint8_t* destination,
                                    size_t destinationLength,
                                    const LI_CLIPBOARD_BLOB_REFERENCE* reference,
                                    size_t* encodedLength) {
    size_t requiredLength;

    if (destination == NULL || reference == NULL || encodedLength == NULL ||
            reference->idLength == 0 || reference->idLength > LI_CLIPBOARD_BLOB_ID_MAX_BYTES ||
            (reference->targetMimeType != LI_CLIPBOARD_MIME_TEXT_UTF8 &&
             reference->targetMimeType != LI_CLIPBOARD_MIME_PNG) ||
            reference->size == 0) {
        return false;
    }

    requiredLength = LI_CLIPBOARD_BLOB_REFERENCE_HEADER_SIZE + reference->idLength;
    if (destinationLength < requiredLength) {
        return false;
    }

    destination[0] = LI_CLIPBOARD_BLOB_REFERENCE_VERSION;
    destination[1] = reference->targetMimeType;
    destination[2] = reference->idLength;
    destination[3] = 0;
    writeLe32(destination + 4, reference->size);
    memcpy(destination + 8, reference->sha256, LI_CLIPBOARD_SHA256_BYTES);
    memcpy(destination + LI_CLIPBOARD_BLOB_REFERENCE_HEADER_SIZE, reference->id, reference->idLength);
    *encodedLength = requiredLength;
    return true;
}

bool LiDecodeClipboardBlobReference(const uint8_t* source,
                                    size_t sourceLength,
                                    PLI_CLIPBOARD_BLOB_REFERENCE reference) {
    uint8_t idLength;

    if (source == NULL || reference == NULL || sourceLength < LI_CLIPBOARD_BLOB_REFERENCE_HEADER_SIZE ||
            source[0] != LI_CLIPBOARD_BLOB_REFERENCE_VERSION ||
            (source[1] != LI_CLIPBOARD_MIME_TEXT_UTF8 && source[1] != LI_CLIPBOARD_MIME_PNG) ||
            source[3] != 0) {
        return false;
    }

    idLength = source[2];
    if (idLength == 0 || idLength > LI_CLIPBOARD_BLOB_ID_MAX_BYTES ||
            sourceLength != LI_CLIPBOARD_BLOB_REFERENCE_HEADER_SIZE + idLength) {
        return false;
    }

    memset(reference, 0, sizeof(*reference));
    reference->targetMimeType = source[1];
    reference->idLength = idLength;
    reference->size = readLe32(source + 4);
    if (reference->size == 0) {
        return false;
    }
    memcpy(reference->sha256, source + 8, LI_CLIPBOARD_SHA256_BYTES);
    memcpy(reference->id, source + LI_CLIPBOARD_BLOB_REFERENCE_HEADER_SIZE, idLength);
    reference->id[idLength] = '\0';
    return true;
}

bool LiIsClipboardMimeSupported(uint8_t mimeType, uint8_t capabilities) {
    switch (mimeType) {
    case LI_CLIPBOARD_MIME_TEXT_UTF8:
        return (capabilities & LI_CLIPBOARD_CAP_TEXT) != 0;
    case LI_CLIPBOARD_MIME_PNG:
        return (capabilities & LI_CLIPBOARD_CAP_PNG) != 0;
    case LI_CLIPBOARD_MIME_BLOB_REFERENCE:
        return (capabilities & LI_CLIPBOARD_CAP_BLOB) != 0;
    default:
        return false;
    }
}

uint32_t LiGetClipboardMimeSizeLimit(uint8_t mimeType) {
    switch (mimeType) {
    case LI_CLIPBOARD_MIME_TEXT_UTF8:
        return LI_CLIPBOARD_MAX_TEXT_BYTES;
    case LI_CLIPBOARD_MIME_PNG:
        return LI_CLIPBOARD_MAX_PNG_INLINE_BYTES;
    case LI_CLIPBOARD_MIME_BLOB_REFERENCE:
        return LI_CLIPBOARD_MAX_BLOB_REFERENCE_BYTES;
    default:
        return 0;
    }
}

bool LiIsValidUtf8ClipboardText(const uint8_t* text, size_t length) {
    size_t position = 0;

    if (text == NULL && length != 0) {
        return false;
    }

    while (position < length) {
        uint8_t first = text[position++];
        uint32_t codepoint;
        unsigned continuationCount;

        if (first == 0) {
            return false;
        }
        if (first < 0x80) {
            continue;
        }
        if (first >= 0xC2 && first <= 0xDF) {
            codepoint = first & 0x1F;
            continuationCount = 1;
        }
        else if (first >= 0xE0 && first <= 0xEF) {
            codepoint = first & 0x0F;
            continuationCount = 2;
        }
        else if (first >= 0xF0 && first <= 0xF4) {
            codepoint = first & 0x07;
            continuationCount = 3;
        }
        else {
            return false;
        }

        if (continuationCount > length - position) {
            return false;
        }

        for (unsigned i = 0; i < continuationCount; i++) {
            uint8_t continuation = text[position++];
            if ((continuation & 0xC0) != 0x80) {
                return false;
            }
            codepoint = (codepoint << 6) | (continuation & 0x3F);
        }

        if ((continuationCount == 1 && codepoint < 0x80) ||
                (continuationCount == 2 && codepoint < 0x800) ||
                (continuationCount == 3 && codepoint < 0x10000) ||
                codepoint > 0x10FFFF ||
                (codepoint >= 0xD800 && codepoint <= 0xDFFF)) {
            return false;
        }
    }

    return true;
}

bool LiIsValidClipboardPngHeader(const uint8_t* png, size_t length) {
    static const uint8_t pngSignature[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    uint32_t width;
    uint32_t height;

    if (png == NULL || length < 24 ||
            memcmp(png, pngSignature, sizeof(pngSignature)) != 0 ||
            readBe32(png + 8) != 13 ||
            memcmp(png + 12, "IHDR", 4) != 0) {
        return false;
    }

    width = readBe32(png + 16);
    height = readBe32(png + 20);
    return width != 0 && height != 0 &&
           (uint64_t)width * height <= LI_CLIPBOARD_MAX_IMAGE_PIXELS;
}
