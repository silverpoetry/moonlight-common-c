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

bool LiEncodeClipboardHeader(uint8_t* destination,
                             size_t destinationLength,
                             const LI_CLIPBOARD_HEADER* header) {
    if (destination == NULL || header == NULL || destinationLength < LI_CLIPBOARD_HEADER_SIZE) {
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

bool LiDecodeClipboardHeader(const uint8_t* source,
                             size_t sourceLength,
                             PLI_CLIPBOARD_HEADER header) {
    if (source == NULL || header == NULL || sourceLength < LI_CLIPBOARD_HEADER_SIZE) {
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
            (source[1] != LI_CLIPBOARD_MIME_TEXT_UTF8 &&
             source[1] != LI_CLIPBOARD_MIME_PNG) ||
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

bool LiEncodeClipboardFileOffer(uint8_t* destination,
                                size_t destinationLength,
                                const LI_CLIPBOARD_FILE_OFFER* offer,
                                size_t* encodedLength) {
    size_t requiredLength;

    if (destination == NULL || offer == NULL || encodedLength == NULL ||
            offer->idLength == 0 ||
            offer->idLength > LI_CLIPBOARD_FILE_OFFER_ID_MAX_BYTES) {
        return false;
    }

    requiredLength = LI_CLIPBOARD_FILE_OFFER_HEADER_SIZE + offer->idLength;
    if (destinationLength < requiredLength) {
        return false;
    }

    memcpy(destination, "MLFO", 4);
    destination[4] = LI_CLIPBOARD_FILE_OFFER_VERSION;
    destination[5] = offer->idLength;
    destination[6] = 0;
    destination[7] = 0;
    memcpy(destination + LI_CLIPBOARD_FILE_OFFER_HEADER_SIZE,
           offer->id,
           offer->idLength);
    *encodedLength = requiredLength;
    return true;
}

bool LiDecodeClipboardFileOffer(const uint8_t* source,
                                size_t sourceLength,
                                PLI_CLIPBOARD_FILE_OFFER offer) {
    uint8_t idLength;

    if (source == NULL || offer == NULL ||
            sourceLength < LI_CLIPBOARD_FILE_OFFER_HEADER_SIZE ||
            memcmp(source, "MLFO", 4) != 0 ||
            source[4] != LI_CLIPBOARD_FILE_OFFER_VERSION ||
            source[6] != 0 || source[7] != 0) {
        return false;
    }

    idLength = source[5];
    if (idLength == 0 ||
            idLength > LI_CLIPBOARD_FILE_OFFER_ID_MAX_BYTES ||
            sourceLength != LI_CLIPBOARD_FILE_OFFER_HEADER_SIZE + idLength) {
        return false;
    }

    memset(offer, 0, sizeof(*offer));
    offer->idLength = idLength;
    memcpy(offer->id,
           source + LI_CLIPBOARD_FILE_OFFER_HEADER_SIZE,
           idLength);
    offer->id[idLength] = '\0';
    return true;
}

static bool isAsciiEqualIgnoreCase(const uint8_t* value, size_t length, const char* expected) {
    size_t expectedLength = strlen(expected);

    if (length != expectedLength) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        uint8_t character = value[i];
        if (character >= 'a' && character <= 'z') {
            character = (uint8_t)(character - ('a' - 'A'));
        }
        if (character != (uint8_t)expected[i]) {
            return false;
        }
    }
    return true;
}

static bool isReservedWindowsPathSegment(const uint8_t* segment, size_t length) {
    size_t baseLength = 0;

    while (baseLength < length && segment[baseLength] != '.') {
        baseLength++;
    }
    if (isAsciiEqualIgnoreCase(segment, baseLength, "CON") ||
            isAsciiEqualIgnoreCase(segment, baseLength, "PRN") ||
            isAsciiEqualIgnoreCase(segment, baseLength, "AUX") ||
            isAsciiEqualIgnoreCase(segment, baseLength, "NUL")) {
        return true;
    }
    if (baseLength == 4 &&
            (((segment[0] == 'C' || segment[0] == 'c') &&
              (segment[1] == 'O' || segment[1] == 'o') &&
              (segment[2] == 'M' || segment[2] == 'm')) ||
             ((segment[0] == 'L' || segment[0] == 'l') &&
              (segment[1] == 'P' || segment[1] == 'p') &&
              (segment[2] == 'T' || segment[2] == 't'))) &&
            segment[3] >= '1' && segment[3] <= '9') {
        return true;
    }
    return false;
}

static bool isValidClipboardFilePath(const uint8_t* path, size_t length) {
    size_t segmentStart = 0;

    if (path == NULL || length == 0 || length > LI_CLIPBOARD_MAX_FILE_PATH_BYTES ||
            path[0] == '/' || path[length - 1] == '/' ||
            !LiIsValidUtf8ClipboardText(path, length)) {
        return false;
    }

    for (size_t i = 0; i <= length; i++) {
        if (i != length && path[i] != '/') {
            const uint8_t character = path[i];
            if (character < 0x20 || character == 0x7F ||
                    character == '\\' || character == ':' || character == '*' ||
                    character == '?' || character == '"' || character == '<' ||
                    character == '>' || character == '|') {
                return false;
            }
            continue;
        }

        const size_t segmentLength = i - segmentStart;
        if (segmentLength == 0 ||
                (segmentLength == 1 && path[segmentStart] == '.') ||
                (segmentLength == 2 && path[segmentStart] == '.' && path[segmentStart + 1] == '.') ||
                path[i - 1] == '.' || path[i - 1] == ' ' ||
                isReservedWindowsPathSegment(path + segmentStart, segmentLength)) {
            return false;
        }
        segmentStart = i + 1;
    }
    return true;
}

bool LiEncodeClipboardFileManifestHeader(uint8_t* destination,
                                         size_t destinationLength,
                                         const LI_CLIPBOARD_FILE_MANIFEST_HEADER* header) {
    if (destination == NULL || header == NULL ||
            destinationLength < LI_CLIPBOARD_FILE_MANIFEST_HEADER_SIZE ||
            header->entryCount == 0 || header->entryCount > LI_CLIPBOARD_MAX_FILE_ENTRIES ||
            header->fileCount > header->entryCount ||
            header->totalFileBytes > LI_CLIPBOARD_MAX_FILE_TRANSFER_BYTES) {
        return false;
    }

    memcpy(destination, "MLFM", 4);
    destination[4] = LI_CLIPBOARD_FILE_MANIFEST_VERSION;
    destination[5] = 0;
    destination[6] = 0;
    destination[7] = 0;
    writeLe32(destination + 8, header->entryCount);
    writeLe32(destination + 12, header->fileCount);
    writeLe64(destination + 16, header->totalFileBytes);
    return true;
}

bool LiDecodeClipboardFileManifestHeader(const uint8_t* source,
                                         size_t sourceLength,
                                         PLI_CLIPBOARD_FILE_MANIFEST_HEADER header) {
    if (source == NULL || header == NULL ||
            sourceLength < LI_CLIPBOARD_FILE_MANIFEST_HEADER_SIZE ||
            memcmp(source, "MLFM", 4) != 0 ||
            source[4] != LI_CLIPBOARD_FILE_MANIFEST_VERSION ||
            source[5] != 0 || source[6] != 0 || source[7] != 0) {
        return false;
    }

    header->entryCount = readLe32(source + 8);
    header->fileCount = readLe32(source + 12);
    header->totalFileBytes = readLe64(source + 16);
    return header->entryCount != 0 &&
           header->entryCount <= LI_CLIPBOARD_MAX_FILE_ENTRIES &&
           header->fileCount <= header->entryCount &&
           header->totalFileBytes <= LI_CLIPBOARD_MAX_FILE_TRANSFER_BYTES;
}

bool LiEncodeClipboardFileManifestEntry(uint8_t* destination,
                                        size_t destinationLength,
                                        const LI_CLIPBOARD_FILE_MANIFEST_ENTRY* entry,
                                        size_t* encodedLength) {
    size_t requiredLength;

    if (destination == NULL || entry == NULL || encodedLength == NULL ||
            (entry->type != LI_CLIPBOARD_FILE_TYPE_REGULAR &&
             entry->type != LI_CLIPBOARD_FILE_TYPE_DIRECTORY) ||
            !isValidClipboardFilePath(entry->path, entry->pathLength) ||
            (entry->type == LI_CLIPBOARD_FILE_TYPE_DIRECTORY && entry->size != 0) ||
            entry->size > LI_CLIPBOARD_MAX_FILE_BYTES) {
        return false;
    }

    requiredLength = LI_CLIPBOARD_FILE_MANIFEST_ENTRY_HEADER_SIZE + entry->pathLength;
    if (destinationLength < requiredLength) {
        return false;
    }

    destination[0] = entry->type;
    destination[1] = 0;
    destination[2] = 0;
    destination[3] = 0;
    writeLe32(destination + 4, entry->pathLength);
    writeLe64(destination + 8, entry->size);
    writeLe64(destination + 16, entry->modifiedTimeMs);
    memcpy(destination + LI_CLIPBOARD_FILE_MANIFEST_ENTRY_HEADER_SIZE, entry->path, entry->pathLength);
    *encodedLength = requiredLength;
    return true;
}

bool LiDecodeClipboardFileManifestEntry(const uint8_t* source,
                                        size_t sourceLength,
                                        size_t* offset,
                                        PLI_CLIPBOARD_FILE_MANIFEST_ENTRY entry) {
    size_t position;
    uint32_t pathLength;

    if (source == NULL || offset == NULL || entry == NULL ||
            *offset < LI_CLIPBOARD_FILE_MANIFEST_HEADER_SIZE ||
            *offset > sourceLength ||
            sourceLength - *offset < LI_CLIPBOARD_FILE_MANIFEST_ENTRY_HEADER_SIZE) {
        return false;
    }

    position = *offset;
    pathLength = readLe32(source + position + 4);
    if ((source[position] != LI_CLIPBOARD_FILE_TYPE_REGULAR &&
         source[position] != LI_CLIPBOARD_FILE_TYPE_DIRECTORY) ||
            source[position + 1] != 0 || source[position + 2] != 0 || source[position + 3] != 0 ||
            pathLength == 0 || pathLength > LI_CLIPBOARD_MAX_FILE_PATH_BYTES ||
            pathLength > sourceLength - position - LI_CLIPBOARD_FILE_MANIFEST_ENTRY_HEADER_SIZE) {
        return false;
    }

    entry->type = source[position];
    entry->pathLength = pathLength;
    entry->size = readLe64(source + position + 8);
    entry->modifiedTimeMs = readLe64(source + position + 16);
    entry->path = source + position + LI_CLIPBOARD_FILE_MANIFEST_ENTRY_HEADER_SIZE;
    if ((entry->type == LI_CLIPBOARD_FILE_TYPE_DIRECTORY && entry->size != 0) ||
            entry->size > LI_CLIPBOARD_MAX_FILE_BYTES ||
            !isValidClipboardFilePath(entry->path, entry->pathLength)) {
        return false;
    }

    *offset = position + LI_CLIPBOARD_FILE_MANIFEST_ENTRY_HEADER_SIZE + pathLength;
    return true;
}

static bool clipboardFilePathsEqual(const LI_CLIPBOARD_FILE_MANIFEST_ENTRY* first,
                                    const LI_CLIPBOARD_FILE_MANIFEST_ENTRY* second) {
    if (first->pathLength != second->pathLength) {
        return false;
    }
    for (uint32_t i = 0; i < first->pathLength; i++) {
        uint8_t firstCharacter = first->path[i];
        uint8_t secondCharacter = second->path[i];
        if (firstCharacter >= 'A' && firstCharacter <= 'Z') {
            firstCharacter = (uint8_t)(firstCharacter + ('a' - 'A'));
        }
        if (secondCharacter >= 'A' && secondCharacter <= 'Z') {
            secondCharacter = (uint8_t)(secondCharacter + ('a' - 'A'));
        }
        if (firstCharacter != secondCharacter) {
            return false;
        }
    }
    return true;
}

static bool clipboardFilePathEqualsBytes(const LI_CLIPBOARD_FILE_MANIFEST_ENTRY* entry,
                                         const uint8_t* path,
                                         size_t pathLength) {
    LI_CLIPBOARD_FILE_MANIFEST_ENTRY pathEntry;

    memset(&pathEntry, 0, sizeof(pathEntry));
    pathEntry.path = path;
    pathEntry.pathLength = (uint32_t)pathLength;
    return clipboardFilePathsEqual(entry, &pathEntry);
}

bool LiIsValidClipboardFileManifest(const uint8_t* manifest, size_t length) {
    LI_CLIPBOARD_FILE_MANIFEST_HEADER header;
    LI_CLIPBOARD_FILE_MANIFEST_ENTRY current;
    uint64_t totalFileBytes = 0;
    uint32_t fileCount = 0;
    uint32_t topLevelCount = 0;
    size_t offset = LI_CLIPBOARD_FILE_MANIFEST_HEADER_SIZE;

    if (manifest == NULL || length > LI_CLIPBOARD_MAX_FILE_MANIFEST_BYTES ||
            !LiDecodeClipboardFileManifestHeader(manifest, length, &header)) {
        return false;
    }

    for (uint32_t i = 0; i < header.entryCount; i++) {
        size_t currentOffset = offset;
        if (!LiDecodeClipboardFileManifestEntry(manifest, length, &offset, &current)) {
            return false;
        }

        if (current.type == LI_CLIPBOARD_FILE_TYPE_REGULAR) {
            if (totalFileBytes > LI_CLIPBOARD_MAX_FILE_TRANSFER_BYTES - current.size) {
                return false;
            }
            totalFileBytes += current.size;
            fileCount++;
        }

        size_t previousOffset = LI_CLIPBOARD_FILE_MANIFEST_HEADER_SIZE;
        bool parentFound = false;
        size_t parentLength = 0;
        for (uint32_t pathIndex = 0; pathIndex < current.pathLength; pathIndex++) {
            if (current.path[pathIndex] == '/') {
                parentLength = pathIndex;
            }
        }
        if (parentLength == 0) {
            topLevelCount++;
            parentFound = true;
        }
        for (uint32_t previousIndex = 0; previousIndex < i; previousIndex++) {
            LI_CLIPBOARD_FILE_MANIFEST_ENTRY previous;
            if (!LiDecodeClipboardFileManifestEntry(manifest, currentOffset, &previousOffset, &previous)) {
                return false;
            }
            if (clipboardFilePathsEqual(&current, &previous)) {
                return false;
            }
            if (parentLength != 0 &&
                    previous.type == LI_CLIPBOARD_FILE_TYPE_DIRECTORY &&
                    clipboardFilePathEqualsBytes(&previous,
                                                 current.path,
                                                 parentLength)) {
                parentFound = true;
            }
        }
        if (!parentFound) {
            return false;
        }
    }

    return offset == length &&
           fileCount == header.fileCount &&
           topLevelCount != 0 &&
           totalFileBytes == header.totalFileBytes;
}

bool LiIsClipboardMimeSupported(uint8_t mimeType, uint8_t capabilities) {
    switch (mimeType) {
    case LI_CLIPBOARD_MIME_TEXT_UTF8:
        return (capabilities & LI_CLIPBOARD_CAP_TEXT) != 0;
    case LI_CLIPBOARD_MIME_PNG:
        return (capabilities & LI_CLIPBOARD_CAP_PNG) != 0;
    case LI_CLIPBOARD_MIME_BLOB_REFERENCE:
        return (capabilities & LI_CLIPBOARD_CAP_BLOB) != 0;
    case LI_CLIPBOARD_MIME_FILE_OFFER:
        return (capabilities &
                (LI_CLIPBOARD_CAP_FILES | LI_CLIPBOARD_CAP_FILE_STREAMS)) ==
               (LI_CLIPBOARD_CAP_FILES | LI_CLIPBOARD_CAP_FILE_STREAMS);
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
    case LI_CLIPBOARD_MIME_FILE_OFFER:
        return LI_CLIPBOARD_MAX_FILE_OFFER_BYTES;
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
