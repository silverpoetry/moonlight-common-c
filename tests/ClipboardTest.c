#include "Clipboard.h"

#include <assert.h>
#include <string.h>

static const char canonicalManifestHex[] =
#include "fixtures/ClipboardManifestV1.inc"
;

static uint8_t hexNibble(char value) {
    if (value >= '0' && value <= '9') {
        return (uint8_t)(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return (uint8_t)(value - 'a' + 10);
    }
    assert(false);
    return 0;
}

static size_t decodeHex(const char* source,
                        uint8_t* destination,
                        size_t destinationLength) {
    size_t sourceLength = strlen(source);
    assert(sourceLength % 2 == 0);
    assert(sourceLength / 2 <= destinationLength);
    for (size_t index = 0; index < sourceLength / 2; index++) {
        destination[index] = (uint8_t)(
            (hexNibble(source[index * 2]) << 4) |
            hexNibble(source[index * 2 + 1]));
    }
    return sourceLength / 2;
}

static void testHeaderRoundTrip(void) {
    LI_CLIPBOARD_HEADER input = {
        .version = LI_CLIPBOARD_VERSION,
        .op = LI_CLIPBOARD_OP_DATA,
        .mimeType = LI_CLIPBOARD_MIME_PNG,
        .flags = LI_CLIPBOARD_CAP_CAN_SEND | LI_CLIPBOARD_CAP_PNG,
        .sequence = 0x11223344,
        .originId = UINT64_C(0x0123456789ABCDEF),
        .itemId = UINT64_C(0xFEDCBA9876543210),
        .totalLength = 123456,
        .chunkOffset = 16384,
        .chunkLength = 8192,
    };
    LI_CLIPBOARD_HEADER output;
    uint8_t encoded[LI_CLIPBOARD_HEADER_SIZE];

    assert(LiEncodeClipboardHeader(encoded, sizeof(encoded), &input));
    assert(LiDecodeClipboardHeader(encoded, sizeof(encoded), &output));
    assert(output.version == input.version);
    assert(output.op == input.op);
    assert(output.mimeType == input.mimeType);
    assert(output.flags == input.flags);
    assert(output.sequence == input.sequence);
    assert(output.originId == input.originId);
    assert(output.itemId == input.itemId);
    assert(output.totalLength == input.totalLength);
    assert(output.chunkOffset == input.chunkOffset);
    assert(output.chunkLength == input.chunkLength);
    assert(!LiEncodeClipboardHeader(encoded, sizeof(encoded) - 1, &input));
    assert(!LiDecodeClipboardHeader(encoded, sizeof(encoded) - 1, &output));
}

static LI_CLIPBOARD_HEADER validMessage(uint8_t op) {
    LI_CLIPBOARD_HEADER header = {
        .version = LI_CLIPBOARD_VERSION,
        .op = op,
        .mimeType = LI_CLIPBOARD_MIME_TEXT_UTF8,
        .flags = 0,
        .sequence = 1,
        .originId = 2,
        .itemId = 3,
        .totalLength = 4,
        .chunkOffset = 0,
        .chunkLength = 0,
    };

    if (op == LI_CLIPBOARD_OP_HELLO) {
        header.mimeType = LI_CLIPBOARD_MIME_NONE;
        header.flags = LI_CLIPBOARD_CAP_CAN_SEND | LI_CLIPBOARD_CAP_TEXT;
        header.itemId = 0;
        header.totalLength = 0;
    }
    else if (op == LI_CLIPBOARD_OP_DATA) {
        header.chunkLength = 4;
    }
    else if (op == LI_CLIPBOARD_OP_ACK || op == LI_CLIPBOARD_OP_NACK) {
        header.totalLength = 0;
    }
    else if (op == LI_CLIPBOARD_OP_RELEASE) {
        header.mimeType = LI_CLIPBOARD_MIME_NONE;
        header.totalLength = 0;
    }
    return header;
}

static void testCapabilityValidation(void) {
    assert(LiIsValidClipboardCapabilities(
        LI_CLIPBOARD_CAP_CAN_SEND | LI_CLIPBOARD_CAP_TEXT));
    assert(LiIsValidClipboardCapabilities(
        LI_CLIPBOARD_CAP_CAN_RECEIVE | LI_CLIPBOARD_CAP_TEXT |
        LI_CLIPBOARD_CAP_BLOB));
    assert(LiIsValidClipboardCapabilities(
        LI_CLIPBOARD_CAP_CAN_SEND | LI_CLIPBOARD_CAP_FILES |
        LI_CLIPBOARD_CAP_FILE_STREAMS));
    assert(!LiIsValidClipboardCapabilities(LI_CLIPBOARD_CAP_TEXT));
    assert(!LiIsValidClipboardCapabilities(
        LI_CLIPBOARD_CAP_CAN_SEND | LI_CLIPBOARD_CAP_FILES));
    assert(!LiIsValidClipboardCapabilities(
        LI_CLIPBOARD_CAP_CAN_SEND | LI_CLIPBOARD_CAP_FILE_STREAMS));
    assert(!LiIsValidClipboardCapabilities(
        LI_CLIPBOARD_CAP_CAN_SEND | LI_CLIPBOARD_CAP_FILES |
        LI_CLIPBOARD_CAP_FILE_STREAMS | LI_CLIPBOARD_CAP_BLOB));
    assert(!LiIsValidClipboardCapabilities(
        LI_CLIPBOARD_CAP_CAN_SEND | LI_CLIPBOARD_CAP_TEXT | 0x80));
}

static void testMessageValidation(void) {
    const uint8_t operations[] = {
        LI_CLIPBOARD_OP_HELLO,
        LI_CLIPBOARD_OP_ANNOUNCE,
        LI_CLIPBOARD_OP_REQUEST,
        LI_CLIPBOARD_OP_DATA,
        LI_CLIPBOARD_OP_ACK,
        LI_CLIPBOARD_OP_NACK,
        LI_CLIPBOARD_OP_RELEASE,
    };

    for (size_t i = 0; i < sizeof(operations); i++) {
        LI_CLIPBOARD_HEADER header = validMessage(operations[i]);
        assert(LiIsValidClipboardMessage(
            &header, LI_CLIPBOARD_HEADER_SIZE + header.chunkLength));

        header.sequence = 0;
        assert(!LiIsValidClipboardMessage(
            &header, LI_CLIPBOARD_HEADER_SIZE + header.chunkLength));
    }

    LI_CLIPBOARD_HEADER header = validMessage(LI_CLIPBOARD_OP_DATA);
    assert(!LiIsValidClipboardMessage(
        &header, LI_CLIPBOARD_HEADER_SIZE + header.chunkLength - 1));
    header.flags = LI_CLIPBOARD_CAP_TEXT;
    assert(!LiIsValidClipboardMessage(
        &header, LI_CLIPBOARD_HEADER_SIZE + header.chunkLength));

    header = validMessage(LI_CLIPBOARD_OP_RELEASE);
    header.itemId = 0;
    assert(!LiIsValidClipboardMessage(&header, LI_CLIPBOARD_HEADER_SIZE));
}

static void testBlobReferenceRoundTrip(void) {
    LI_CLIPBOARD_BLOB_REFERENCE input = {
        .targetMimeType = LI_CLIPBOARD_MIME_PNG,
        .size = 1234567,
        .idLength = 36,
        .id = "01234567-89ab-4cde-8fab-0123456789ab",
    };
    LI_CLIPBOARD_BLOB_REFERENCE output;
    uint8_t encoded[LI_CLIPBOARD_MAX_BLOB_REFERENCE_BYTES];
    size_t encodedLength = 0;

    for (size_t i = 0; i < sizeof(input.sha256); i++) {
        input.sha256[i] = (uint8_t)i;
    }

    assert(LiEncodeClipboardBlobReference(encoded, sizeof(encoded), &input, &encodedLength));
    assert(encodedLength ==
           (size_t)LI_CLIPBOARD_BLOB_REFERENCE_HEADER_SIZE + input.idLength);
    assert(LiDecodeClipboardBlobReference(encoded, encodedLength, &output));
    assert(output.targetMimeType == input.targetMimeType);
    assert(output.size == input.size);
    assert(output.idLength == input.idLength);
    assert(strcmp(output.id, input.id) == 0);
    assert(memcmp(output.sha256, input.sha256, sizeof(input.sha256)) == 0);

}

static void testFileOfferRoundTrip(void) {
    LI_CLIPBOARD_FILE_OFFER input = {
        .idLength = 36,
        .id = "01234567-89ab-4cde-8fab-0123456789ab",
    };
    LI_CLIPBOARD_FILE_OFFER output;
    uint8_t encoded[LI_CLIPBOARD_MAX_FILE_OFFER_BYTES];
    size_t encodedLength = 0;

    assert(LiEncodeClipboardFileOffer(encoded,
                                      sizeof(encoded),
                                      &input,
                                      &encodedLength));
    assert(encodedLength ==
           (size_t)LI_CLIPBOARD_FILE_OFFER_HEADER_SIZE + input.idLength);
    assert(LiDecodeClipboardFileOffer(encoded, encodedLength, &output));
    assert(output.idLength == input.idLength);
    assert(strcmp(output.id, input.id) == 0);

    encoded[6] = 1;
    assert(!LiDecodeClipboardFileOffer(encoded, encodedLength, &output));
}

static void testUtf8Validation(void) {
    static const uint8_t valid[] = "ASCII \xE4\xB8\xAD\xE6\x96\x87 \xF0\x9F\x98\x80";
    static const uint8_t overlong[] = {0xC0, 0xAF};
    static const uint8_t surrogate[] = {0xED, 0xA0, 0x80};
    static const uint8_t truncated[] = {0xF0, 0x9F, 0x98};
    static const uint8_t embeddedNull[] = {'a', 0, 'b'};

    assert(LiIsValidUtf8ClipboardText(valid, sizeof(valid) - 1));
    assert(LiIsValidUtf8ClipboardText(NULL, 0));
    assert(!LiIsValidUtf8ClipboardText(overlong, sizeof(overlong)));
    assert(!LiIsValidUtf8ClipboardText(surrogate, sizeof(surrogate)));
    assert(!LiIsValidUtf8ClipboardText(truncated, sizeof(truncated)));
    assert(!LiIsValidUtf8ClipboardText(embeddedNull, sizeof(embeddedNull)));
}

static void testPngHeaderValidation(void) {
    static const uint8_t validHeader[] = {
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 'I', 'H', 'D', 'R',
        0x00, 0x00, 0x07, 0x80, 0x00, 0x00, 0x04, 0x38,
    };
    uint8_t invalidHeader[sizeof(validHeader)];

    assert(LiIsValidClipboardPngHeader(validHeader, sizeof(validHeader)));
    memcpy(invalidHeader, validHeader, sizeof(validHeader));
    invalidHeader[16] = 0x7F;
    assert(!LiIsValidClipboardPngHeader(invalidHeader, sizeof(invalidHeader)));
}

static size_t appendManifestEntry(uint8_t* manifest,
                                  size_t capacity,
                                  size_t offset,
                                  uint8_t type,
                                  const char* path,
                                  uint64_t size) {
    LI_CLIPBOARD_FILE_MANIFEST_ENTRY entry = {
        .type = type,
        .pathLength = (uint32_t)strlen(path),
        .size = size,
        .modifiedTimeMs = UINT64_C(1720000000000),
        .path = (const uint8_t*)path,
    };
    size_t encodedLength = 0;

    assert(LiEncodeClipboardFileManifestEntry(manifest + offset,
                                              capacity - offset,
                                              &entry,
                                              &encodedLength));
    return offset + encodedLength;
}

static void testFileManifestValidation(void) {
    uint8_t manifest[512];
    uint8_t canonicalManifest[512];
    LI_CLIPBOARD_FILE_MANIFEST_HEADER header = {
        .entryCount = 3,
        .fileCount = 2,
        .totalFileBytes = 15,
    };
    LI_CLIPBOARD_FILE_MANIFEST_HEADER decodedHeader;
    LI_CLIPBOARD_FILE_MANIFEST_ENTRY decodedEntry;
    size_t offset = LI_CLIPBOARD_FILE_MANIFEST_HEADER_SIZE;

    assert(LiEncodeClipboardFileManifestHeader(manifest, sizeof(manifest), &header));
    offset = appendManifestEntry(manifest, sizeof(manifest), offset,
                                 LI_CLIPBOARD_FILE_TYPE_DIRECTORY, "folder", 0);
    offset = appendManifestEntry(manifest, sizeof(manifest), offset,
                                 LI_CLIPBOARD_FILE_TYPE_REGULAR, "folder/one.txt", 10);
    offset = appendManifestEntry(manifest, sizeof(manifest), offset,
                                 LI_CLIPBOARD_FILE_TYPE_REGULAR, "two.bin", 5);

    assert(LiIsValidClipboardFileManifest(manifest, offset));
    size_t canonicalLength = decodeHex(canonicalManifestHex,
                                       canonicalManifest,
                                       sizeof(canonicalManifest));
    assert(offset == canonicalLength);
    assert(memcmp(manifest, canonicalManifest, canonicalLength) == 0);
    assert(LiDecodeClipboardFileManifestHeader(manifest, offset, &decodedHeader));
    assert(decodedHeader.entryCount == 3);
    size_t decodeOffset = LI_CLIPBOARD_FILE_MANIFEST_HEADER_SIZE;
    assert(LiDecodeClipboardFileManifestEntry(manifest, offset, &decodeOffset, &decodedEntry));
    assert(decodedEntry.type == LI_CLIPBOARD_FILE_TYPE_DIRECTORY);
    assert(decodedEntry.pathLength == strlen("folder"));
    assert(memcmp(decodedEntry.path, "folder", decodedEntry.pathLength) == 0);

    manifest[5] = 1;
    assert(!LiIsValidClipboardFileManifest(manifest, offset));
    manifest[5] = 0;

    manifest[offset - strlen("two.bin")] = '/';
    assert(!LiIsValidClipboardFileManifest(manifest, offset));
}

static void testFileManifestRejectsUnsafePaths(void) {
    uint8_t encoded[128];
    size_t encodedLength;
    const char* unsafePaths[] = {
        "../secret.txt",
        "folder\\file.txt",
        "C:/file.txt",
        "folder//file.txt",
        "CON.txt",
        "file. ",
    };

    for (size_t i = 0; i < sizeof(unsafePaths) / sizeof(unsafePaths[0]); i++) {
        LI_CLIPBOARD_FILE_MANIFEST_ENTRY entry = {
            .type = LI_CLIPBOARD_FILE_TYPE_REGULAR,
            .pathLength = (uint32_t)strlen(unsafePaths[i]),
            .size = 1,
            .path = (const uint8_t*)unsafePaths[i],
        };
        assert(!LiEncodeClipboardFileManifestEntry(encoded, sizeof(encoded), &entry, &encodedLength));
    }

    LI_CLIPBOARD_FILE_MANIFEST_HEADER header = {
        .entryCount = 1,
        .fileCount = 1,
        .totalFileBytes = 1,
    };
    assert(LiEncodeClipboardFileManifestHeader(encoded, sizeof(encoded), &header));
    size_t length = appendManifestEntry(encoded, sizeof(encoded),
                                        LI_CLIPBOARD_FILE_MANIFEST_HEADER_SIZE,
                                        LI_CLIPBOARD_FILE_TYPE_REGULAR,
                                        "missing/file.txt",
                                        1);
    assert(!LiIsValidClipboardFileManifest(encoded, length));
}

static void testFileStreamingCapability(void) {
    assert(!LiIsClipboardMimeSupported(LI_CLIPBOARD_MIME_FILE_OFFER,
                                       LI_CLIPBOARD_CAP_FILES));
    assert(!LiIsClipboardMimeSupported(LI_CLIPBOARD_MIME_FILE_OFFER,
                                       LI_CLIPBOARD_CAP_FILE_STREAMS));
    assert(LiIsClipboardMimeSupported(
        LI_CLIPBOARD_MIME_FILE_OFFER,
        LI_CLIPBOARD_CAP_FILES | LI_CLIPBOARD_CAP_FILE_STREAMS));
}

int main(void) {
    testHeaderRoundTrip();
    testCapabilityValidation();
    testMessageValidation();
    testBlobReferenceRoundTrip();
    testFileOfferRoundTrip();
    testUtf8Validation();
    testPngHeaderValidation();
    testFileManifestValidation();
    testFileManifestRejectsUnsafePaths();
    testFileStreamingCapability();
    return 0;
}
