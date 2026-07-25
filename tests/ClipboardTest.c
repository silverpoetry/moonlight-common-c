#include "Clipboard.h"

#include <assert.h>
#include <string.h>

static void testHeaderRoundTrip(void) {
    LI_CLIPBOARD_V2_HEADER input = {
        .version = LI_CLIPBOARD_VERSION_V2,
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
    LI_CLIPBOARD_V2_HEADER output;
    uint8_t encoded[LI_CLIPBOARD_V2_HEADER_SIZE];

    assert(LiEncodeClipboardV2Header(encoded, sizeof(encoded), &input));
    assert(LiDecodeClipboardV2Header(encoded, sizeof(encoded), &output));
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
    assert(!LiEncodeClipboardV2Header(encoded, sizeof(encoded) - 1, &input));
    assert(!LiDecodeClipboardV2Header(encoded, sizeof(encoded) - 1, &output));
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
    assert(encodedLength == LI_CLIPBOARD_BLOB_REFERENCE_HEADER_SIZE + input.idLength);
    assert(LiDecodeClipboardBlobReference(encoded, encodedLength, &output));
    assert(output.targetMimeType == input.targetMimeType);
    assert(output.size == input.size);
    assert(output.idLength == input.idLength);
    assert(strcmp(output.id, input.id) == 0);
    assert(memcmp(output.sha256, input.sha256, sizeof(input.sha256)) == 0);
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

int main(void) {
    testHeaderRoundTrip();
    testBlobReferenceRoundTrip();
    testUtf8Validation();
    testPngHeaderValidation();
    return 0;
}
