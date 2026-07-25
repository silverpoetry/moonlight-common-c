#include "Limelight-internal.h"
#include "Srtp.h"

static bool deriveSessionValue(const uint8_t masterKey[SRTP_AES_128_KEY_LENGTH],
                               const uint8_t masterSalt[SRTP_AEAD_SALT_LENGTH],
                               uint8_t label, uint8_t* output, size_t outputLength) {
    uint8_t aesInput[16] = { 0 };
    uint8_t aesOutput[16];

    LC_ASSERT(outputLength <= sizeof(aesOutput));

    // RFC 7714 uses the RFC 3711 AES-CM PRF. AES-GCM has a 12-byte
    // master salt, so it is zero-extended to the legacy 14-byte KDF salt
    // before the final two zero bytes for the AES-CM counter are appended.
    memcpy(aesInput, masterSalt, SRTP_AEAD_SALT_LENGTH);
    aesInput[7] ^= label;

    if (!PltAesEcbEncryptBlock(masterKey, SRTP_AES_128_KEY_LENGTH, aesInput, aesOutput)) {
        memset(aesOutput, 0, sizeof(aesOutput));
        return false;
    }

    memcpy(output, aesOutput, outputLength);
    memset(aesOutput, 0, sizeof(aesOutput));
    return true;
}

bool SrtpDeriveSessionKeys(const uint8_t inputKey[16],
                           const uint8_t inputIv[16],
                           const uint8_t audioPingPayload[16],
                           PSRTP_SESSION_KEYS sessionKeys) {
    static const uint8_t infoPrefix[] = MICROPHONE_SRTP_HKDF_INFO;
    uint8_t info[(sizeof(infoPrefix) - 1) + 16];
    uint8_t masterMaterial[SRTP_AES_128_KEY_LENGTH + SRTP_AEAD_SALT_LENGTH];
    const uint8_t* masterKey = masterMaterial;
    const uint8_t* masterSalt = masterMaterial + SRTP_AES_128_KEY_LENGTH;
    bool success = false;

    if (inputKey == NULL || inputIv == NULL || audioPingPayload == NULL || sessionKeys == NULL) {
        return false;
    }

    memcpy(info, infoPrefix, sizeof(infoPrefix) - 1);
    memcpy(info + sizeof(infoPrefix) - 1, audioPingPayload, 16);

    if (!PltHkdfSha256(inputKey, 16,
                       inputIv, 16,
                       info, sizeof(info),
                       masterMaterial, sizeof(masterMaterial))) {
        goto Exit;
    }

    if (!deriveSessionValue(masterKey, masterSalt, SRTP_RTP_ENCRYPTION_LABEL,
                            sessionKeys->rtpKey, sizeof(sessionKeys->rtpKey)) ||
        !deriveSessionValue(masterKey, masterSalt, SRTP_RTP_SALT_LABEL,
                            sessionKeys->rtpSalt, sizeof(sessionKeys->rtpSalt)) ||
        !deriveSessionValue(masterKey, masterSalt, SRTP_RTCP_ENCRYPTION_LABEL,
                            sessionKeys->rtcpKey, sizeof(sessionKeys->rtcpKey)) ||
        !deriveSessionValue(masterKey, masterSalt, SRTP_RTCP_SALT_LABEL,
                            sessionKeys->rtcpSalt, sizeof(sessionKeys->rtcpSalt))) {
        goto Exit;
    }

    success = true;

Exit:
    if (!success) {
        memset(sessionKeys, 0, sizeof(*sessionKeys));
    }
    memset(masterMaterial, 0, sizeof(masterMaterial));
    return success;
}

void SrtpCreateRtpAeadIv(const uint8_t salt[SRTP_AEAD_SALT_LENGTH],
                         uint32_t ssrc, uint32_t rolloverCounter, uint16_t sequenceNumber,
                         uint8_t iv[SRTP_AEAD_SALT_LENGTH]) {
    uint8_t packetIndex[SRTP_AEAD_SALT_LENGTH] = {
        0,
        0,
        (uint8_t)(ssrc >> 24),
        (uint8_t)(ssrc >> 16),
        (uint8_t)(ssrc >> 8),
        (uint8_t)ssrc,
        (uint8_t)(rolloverCounter >> 24),
        (uint8_t)(rolloverCounter >> 16),
        (uint8_t)(rolloverCounter >> 8),
        (uint8_t)rolloverCounter,
        (uint8_t)(sequenceNumber >> 8),
        (uint8_t)sequenceNumber,
    };

    for (size_t i = 0; i < SRTP_AEAD_SALT_LENGTH; i++) {
        iv[i] = salt[i] ^ packetIndex[i];
    }
}

void SrtpCreateRtcpAeadIv(const uint8_t salt[SRTP_AEAD_SALT_LENGTH],
                          uint32_t ssrc, uint32_t srtcpIndex,
                          uint8_t iv[SRTP_AEAD_SALT_LENGTH]) {
    uint8_t packetIndex[SRTP_AEAD_SALT_LENGTH] = {
        0,
        0,
        (uint8_t)(ssrc >> 24),
        (uint8_t)(ssrc >> 16),
        (uint8_t)(ssrc >> 8),
        (uint8_t)ssrc,
        0,
        0,
        (uint8_t)(srtcpIndex >> 24),
        (uint8_t)(srtcpIndex >> 16),
        (uint8_t)(srtcpIndex >> 8),
        (uint8_t)srtcpIndex,
    };

    for (size_t i = 0; i < SRTP_AEAD_SALT_LENGTH; i++) {
        iv[i] = salt[i] ^ packetIndex[i];
    }
}
