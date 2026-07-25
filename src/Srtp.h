#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ML_MICROPHONE_UPLINK_VERSION 1
#define ML_MICROPHONE_PAYLOAD_TYPE 111
#define ML_MICROPHONE_SAMPLE_RATE 48000
#define ML_MICROPHONE_FRAME_SAMPLES 960
#define ML_MICROPHONE_FRAME_DURATION_MS 20

#define SRTP_AES_128_KEY_LENGTH 16
#define SRTP_AEAD_SALT_LENGTH 12
#define SRTP_AEAD_TAG_LENGTH 16

#define SRTP_RTP_ENCRYPTION_LABEL 0x00
#define SRTP_RTP_SALT_LABEL 0x02
#define SRTP_RTCP_ENCRYPTION_LABEL 0x03
#define SRTP_RTCP_SALT_LABEL 0x05

#define MICROPHONE_SRTP_HKDF_INFO "Moonlight/Sunshine audio-uplink SRTP v1"

typedef struct _SRTP_SESSION_KEYS {
    uint8_t rtpKey[SRTP_AES_128_KEY_LENGTH];
    uint8_t rtpSalt[SRTP_AEAD_SALT_LENGTH];
    uint8_t rtcpKey[SRTP_AES_128_KEY_LENGTH];
    uint8_t rtcpSalt[SRTP_AEAD_SALT_LENGTH];
} SRTP_SESSION_KEYS, *PSRTP_SESSION_KEYS;

bool SrtpDeriveSessionKeys(const uint8_t inputKey[16],
                           const uint8_t inputIv[16],
                           const uint8_t audioPingPayload[16],
                           PSRTP_SESSION_KEYS sessionKeys);

void SrtpCreateRtpAeadIv(const uint8_t salt[SRTP_AEAD_SALT_LENGTH],
                         uint32_t ssrc, uint32_t rolloverCounter, uint16_t sequenceNumber,
                         uint8_t iv[SRTP_AEAD_SALT_LENGTH]);

void SrtpCreateRtcpAeadIv(const uint8_t salt[SRTP_AEAD_SALT_LENGTH],
                          uint32_t ssrc, uint32_t srtcpIndex,
                          uint8_t iv[SRTP_AEAD_SALT_LENGTH]);

