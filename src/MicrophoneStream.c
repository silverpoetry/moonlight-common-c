#include "Limelight-internal.h"
#include "Srtp.h"

#define MICROPHONE_QUEUE_BOUND 4
#define MAX_MICROPHONE_OPUS_PAYLOAD 1200
#define RTP_HEADER_LENGTH 12
#define RTCP_HEADER_LENGTH 8

typedef struct _QUEUED_MICROPHONE_FRAME {
    LINKED_BLOCKING_QUEUE_ENTRY entry;
    uint16_t opusLength;
    uint16_t sampleCount;
    uint32_t timestamp;
    uint8_t flags;
    uint8_t opusData[MAX_MICROPHONE_OPUS_PAYLOAD];
} QUEUED_MICROPHONE_FRAME, *PQUEUED_MICROPHONE_FRAME;

static LINKED_BLOCKING_QUEUE microphoneQueue;
static PLT_THREAD microphoneSendThread;
static PLT_MUTEX microphoneStateMutex;
static bool microphoneStateMutexInitialized;
static bool microphoneQueueInitialized;
static bool microphoneSendThreadStarted;
static bool microphoneActive;

static PPLT_CRYPTO_CONTEXT srtpEncryptionContext;
static PPLT_CRYPTO_CONTEXT srtcpEncryptionContext;
static PPLT_CRYPTO_CONTEXT srtcpDecryptionContext;
static SRTP_SESSION_KEYS srtpSessionKeys;

static uint32_t microphoneSsrc;
static uint32_t nextMicrophoneSsrc;
static uint16_t microphoneSequenceNumber;
static uint32_t microphoneRolloverCounter;
static uint32_t nextCaptureTimestamp;
static uint32_t lastSentTimestamp;
static uint16_t lastSentSampleCount;
static uint64_t lastCaptureTimeUs;
static uint16_t lastCaptureSampleCount;
static uint32_t srtcpSendIndex;
static uint32_t lastReceivedSrtcpIndex;
static bool hasReceivedSrtcp;
static bool markerPending;

static MICROPHONE_UPLINK_STATS microphoneStats;

static void destroyCryptoContext(PPLT_CRYPTO_CONTEXT* context) {
    if (*context != NULL) {
        PltDestroyCryptoContext(*context);
        *context = NULL;
    }
}

static uint16_t readBe16(const uint8_t* data) {
    return ((uint16_t)data[0] << 8) | data[1];
}

static uint32_t readBe32(const uint8_t* data) {
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           data[3];
}

static void writeBe16(uint8_t* data, uint16_t value) {
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

static void writeBe32(uint8_t* data, uint32_t value) {
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static void freeMicrophoneFrames(PLINKED_BLOCKING_QUEUE_ENTRY entry) {
    while (entry != NULL) {
        PLINKED_BLOCKING_QUEUE_ENTRY next = entry->flink;
        free(entry->data);
        entry = next;
    }
}

static void updateSendStats(bool sent) {
    PltLockMutex(&microphoneStateMutex);
    if (sent) {
        microphoneStats.packetsSent++;
    }
    else {
        microphoneStats.sendFailures++;
    }
    PltUnlockMutex(&microphoneStateMutex);
}

static void MicrophoneSendThreadProc(void* context) {
    PQUEUED_MICROPHONE_FRAME frame;

    while (LbqWaitForQueueElement(&microphoneQueue, (void**)&frame) == LBQ_SUCCESS) {
        uint8_t packet[RTP_HEADER_LENGTH + MAX_MICROPHONE_OPUS_PAYLOAD + SRTP_AEAD_TAG_LENGTH];
        uint8_t encryptedPayload[SRTP_AEAD_TAG_LENGTH + MAX_MICROPHONE_OPUS_PAYLOAD];
        uint8_t iv[SRTP_AEAD_SALT_LENGTH];
        int encryptedLength = 0;
        uint16_t sequenceNumber = microphoneSequenceNumber;
        uint32_t rolloverCounter = microphoneRolloverCounter;
        bool marker = markerPending ||
                      (frame->flags & LI_MICROPHONE_FRAME_FLAG_DISCONTINUITY) != 0 ||
                      (lastSentSampleCount != 0 &&
                       frame->timestamp != lastSentTimestamp + lastSentSampleCount);

        packet[0] = 0x80;
        packet[1] = ML_MICROPHONE_PAYLOAD_TYPE | (marker ? 0x80 : 0);
        writeBe16(&packet[2], sequenceNumber);
        writeBe32(&packet[4], frame->timestamp);
        writeBe32(&packet[8], microphoneSsrc);

        SrtpCreateRtpAeadIv(srtpSessionKeys.rtpSalt, microphoneSsrc,
                            rolloverCounter, sequenceNumber, iv);

        // PltEncryptMessageEx() keeps compatibility with the historical
        // [tag][ciphertext] mbedTLS layout. Rearrange it into the RFC 7714
        // wire layout [RTP header][ciphertext][tag] below.
        if (!PltEncryptMessageEx(srtpEncryptionContext, ALGORITHM_AES_GCM, 0,
                                 srtpSessionKeys.rtpKey, sizeof(srtpSessionKeys.rtpKey),
                                 iv, sizeof(iv),
                                 packet, RTP_HEADER_LENGTH,
                                 encryptedPayload, SRTP_AEAD_TAG_LENGTH,
                                 frame->opusData, frame->opusLength,
                                 encryptedPayload + SRTP_AEAD_TAG_LENGTH, &encryptedLength) ||
            encryptedLength != frame->opusLength) {
            Limelog("Microphone SRTP encryption failed\n");
            updateSendStats(false);
            free(frame);
            continue;
        }

        memcpy(packet + RTP_HEADER_LENGTH,
               encryptedPayload + SRTP_AEAD_TAG_LENGTH, encryptedLength);
        memcpy(packet + RTP_HEADER_LENGTH + encryptedLength,
               encryptedPayload, SRTP_AEAD_TAG_LENGTH);

        updateSendStats(sendAudioUdpPacket(packet,
                                           RTP_HEADER_LENGTH + encryptedLength +
                                           SRTP_AEAD_TAG_LENGTH) == 0);

        lastSentTimestamp = frame->timestamp;
        lastSentSampleCount = frame->sampleCount;
        markerPending = false;

        microphoneSequenceNumber++;
        if (microphoneSequenceNumber == 0) {
            microphoneRolloverCounter++;
        }

        free(frame);
    }
}

static void sendSrtcpBye(void) {
    uint8_t packet[RTCP_HEADER_LENGTH + SRTP_AEAD_TAG_LENGTH + sizeof(uint32_t)];
    uint8_t aad[RTCP_HEADER_LENGTH + sizeof(uint32_t)];
    uint8_t tagAndCiphertext[SRTP_AEAD_TAG_LENGTH];
    uint8_t iv[SRTP_AEAD_SALT_LENGTH];
    uint32_t index = srtcpSendIndex++ & 0x7FFFFFFFU;
    uint32_t wireIndex = index | 0x80000000U;
    int encryptedLength = 0;

    packet[0] = 0x81; // V=2, one SSRC
    packet[1] = 203;  // RTCP BYE
    writeBe16(&packet[2], 1);
    writeBe32(&packet[4], microphoneSsrc);

    memcpy(aad, packet, RTCP_HEADER_LENGTH);
    writeBe32(aad + RTCP_HEADER_LENGTH, wireIndex);
    SrtpCreateRtcpAeadIv(srtpSessionKeys.rtcpSalt, microphoneSsrc, index, iv);

    if (!PltEncryptMessageEx(srtcpEncryptionContext, ALGORITHM_AES_GCM, 0,
                             srtpSessionKeys.rtcpKey, sizeof(srtpSessionKeys.rtcpKey),
                             iv, sizeof(iv),
                             aad, sizeof(aad),
                             tagAndCiphertext, SRTP_AEAD_TAG_LENGTH,
                             NULL, 0,
                             tagAndCiphertext + SRTP_AEAD_TAG_LENGTH, &encryptedLength) ||
        encryptedLength != 0) {
        Limelog("Microphone SRTCP BYE encryption failed\n");
        return;
    }

    memcpy(packet + RTCP_HEADER_LENGTH, tagAndCiphertext, SRTP_AEAD_TAG_LENGTH);
    writeBe32(packet + RTCP_HEADER_LENGTH + SRTP_AEAD_TAG_LENGTH, wireIndex);
    sendAudioUdpPacket(packet, sizeof(packet));
}

int initializeMicrophoneStream(void) {
    uint32_t randomSeed;

    memset(&microphoneStats, 0, sizeof(microphoneStats));
    memset(&srtpSessionKeys, 0, sizeof(srtpSessionKeys));
    microphoneQueueInitialized = false;
    microphoneSendThreadStarted = false;
    microphoneActive = false;
    microphoneStateMutexInitialized = false;

    if (PltCreateMutex(&microphoneStateMutex) != 0) {
        return -1;
    }
    microphoneStateMutexInitialized = true;

    PltGenerateRandomData((uint8_t*)&randomSeed, sizeof(randomSeed));
    nextMicrophoneSsrc = randomSeed != 0 ? randomSeed : 1;
    return 0;
}

void destroyMicrophoneStream(void) {
    stopMicrophoneStream();

    if (microphoneStateMutexInitialized) {
        PltDeleteMutex(&microphoneStateMutex);
        microphoneStateMutexInitialized = false;
    }
    memset(&srtpSessionKeys, 0, sizeof(srtpSessionKeys));
}

bool LiIsMicrophoneUplinkSupported(void) {
    return IS_SUNSHINE() &&
           (SunshineFeatureFlags & LI_FF_MICROPHONE_UPLINK) != 0 &&
           AudioPingPayload.payload[0] != 0;
}

int LiStartMicrophoneUplink(void) {
    uint8_t randomState[sizeof(uint16_t) + sizeof(uint32_t)];
    int err;

    if (!LiIsMicrophoneUplinkSupported()) {
        return LI_ERR_UNSUPPORTED;
    }

    PltLockMutex(&microphoneStateMutex);
    if (microphoneActive) {
        PltUnlockMutex(&microphoneStateMutex);
        return 0;
    }

    if (!SrtpDeriveSessionKeys((const uint8_t*)StreamConfig.remoteInputAesKey,
                               (const uint8_t*)StreamConfig.remoteInputAesIv,
                               (const uint8_t*)AudioPingPayload.payload,
                               &srtpSessionKeys)) {
        PltUnlockMutex(&microphoneStateMutex);
        return -1;
    }

    srtpEncryptionContext = PltCreateCryptoContext();
    srtcpEncryptionContext = PltCreateCryptoContext();
    srtcpDecryptionContext = PltCreateCryptoContext();
    if (srtpEncryptionContext == NULL ||
        srtcpEncryptionContext == NULL ||
        srtcpDecryptionContext == NULL) {
        destroyCryptoContext(&srtpEncryptionContext);
        destroyCryptoContext(&srtcpEncryptionContext);
        destroyCryptoContext(&srtcpDecryptionContext);
        memset(&srtpSessionKeys, 0, sizeof(srtpSessionKeys));
        PltUnlockMutex(&microphoneStateMutex);
        return -1;
    }

    if (LbqInitializeLinkedBlockingQueue(&microphoneQueue, MICROPHONE_QUEUE_BOUND) != 0) {
        destroyCryptoContext(&srtpEncryptionContext);
        destroyCryptoContext(&srtcpEncryptionContext);
        destroyCryptoContext(&srtcpDecryptionContext);
        memset(&srtpSessionKeys, 0, sizeof(srtpSessionKeys));
        PltUnlockMutex(&microphoneStateMutex);
        return -1;
    }
    microphoneQueueInitialized = true;

    microphoneSsrc = nextMicrophoneSsrc++;
    if (microphoneSsrc == 0) {
        microphoneSsrc = nextMicrophoneSsrc++;
    }

    PltGenerateRandomData(randomState, sizeof(randomState));
    microphoneSequenceNumber = readBe16(randomState);
    nextCaptureTimestamp = readBe32(randomState + sizeof(uint16_t));
    microphoneRolloverCounter = 0;
    lastSentTimestamp = 0;
    lastSentSampleCount = 0;
    lastCaptureTimeUs = 0;
    lastCaptureSampleCount = 0;
    srtcpSendIndex = 0;
    lastReceivedSrtcpIndex = 0;
    hasReceivedSrtcp = false;
    markerPending = true;

    err = PltCreateThread("MicSend", MicrophoneSendThreadProc, NULL, &microphoneSendThread);
    if (err != 0) {
        freeMicrophoneFrames(LbqDestroyLinkedBlockingQueue(&microphoneQueue));
        microphoneQueueInitialized = false;
        destroyCryptoContext(&srtpEncryptionContext);
        destroyCryptoContext(&srtcpEncryptionContext);
        destroyCryptoContext(&srtcpDecryptionContext);
        memset(&srtpSessionKeys, 0, sizeof(srtpSessionKeys));
        PltUnlockMutex(&microphoneStateMutex);
        return err;
    }

    microphoneSendThreadStarted = true;
    microphoneActive = true;
    PltUnlockMutex(&microphoneStateMutex);
    Limelog("Microphone uplink started (SRTP, 48 kHz mono, 20 ms)\n");
    return 0;
}

int LiSendMicrophoneOpusFrame(const uint8_t* opusData, uint16_t opusLength,
                              uint16_t sampleCount, uint64_t captureTimeUs,
                              uint8_t flags) {
    PQUEUED_MICROPHONE_FRAME frame;
    int queueStatus;

    if (opusData == NULL || opusLength == 0 ||
        opusLength > MAX_MICROPHONE_OPUS_PAYLOAD || sampleCount == 0) {
        return -3;
    }

    frame = malloc(sizeof(*frame));
    if (frame == NULL) {
        return -1;
    }

    frame->opusLength = opusLength;
    frame->sampleCount = sampleCount;
    frame->flags = flags;
    memcpy(frame->opusData, opusData, opusLength);

    PltLockMutex(&microphoneStateMutex);
    if (!microphoneActive) {
        PltUnlockMutex(&microphoneStateMutex);
        free(frame);
        return LI_ERR_UNSUPPORTED;
    }

    if (lastCaptureTimeUs != 0 && captureTimeUs > lastCaptureTimeUs) {
        uint64_t deltaSamples = ((captureTimeUs - lastCaptureTimeUs) *
                                 ML_MICROPHONE_SAMPLE_RATE + 500000) / 1000000;
        if (deltaSamples > lastCaptureSampleCount + lastCaptureSampleCount / 2) {
            nextCaptureTimestamp += (uint32_t)(deltaSamples - lastCaptureSampleCount);
            frame->flags |= LI_MICROPHONE_FRAME_FLAG_DISCONTINUITY;
        }
    }

    frame->timestamp = nextCaptureTimestamp;
    nextCaptureTimestamp += sampleCount;
    lastCaptureTimeUs = captureTimeUs;
    lastCaptureSampleCount = sampleCount;
    microphoneStats.packetsQueued++;

    queueStatus = LbqOfferQueueItem(&microphoneQueue, frame, &frame->entry);
    if (queueStatus == LBQ_BOUND_EXCEEDED) {
        PQUEUED_MICROPHONE_FRAME droppedFrame;

        if (LbqPollQueueElement(&microphoneQueue, (void**)&droppedFrame) == LBQ_SUCCESS) {
            free(droppedFrame);
            microphoneStats.packetsDropped++;
        }
        queueStatus = LbqOfferQueueItem(&microphoneQueue, frame, &frame->entry);
    }
    PltUnlockMutex(&microphoneStateMutex);

    if (queueStatus != LBQ_SUCCESS) {
        free(frame);
        return queueStatus == LBQ_INTERRUPTED ? LI_ERR_UNSUPPORTED : -1;
    }
    return 0;
}

void stopMicrophoneStream(void) {
    if (!microphoneStateMutexInitialized) {
        return;
    }

    PltLockMutex(&microphoneStateMutex);
    if (!microphoneActive) {
        PltUnlockMutex(&microphoneStateMutex);
        return;
    }
    microphoneActive = false;
    if (microphoneQueueInitialized) {
        LbqSignalQueueShutdown(&microphoneQueue);
    }
    PltUnlockMutex(&microphoneStateMutex);

    if (microphoneSendThreadStarted) {
        PltInterruptThread(&microphoneSendThread);
        PltJoinThread(&microphoneSendThread);
        microphoneSendThreadStarted = false;
    }

    if (microphoneQueueInitialized) {
        freeMicrophoneFrames(LbqDestroyLinkedBlockingQueue(&microphoneQueue));
        microphoneQueueInitialized = false;
    }

    sendSrtcpBye();

    destroyCryptoContext(&srtpEncryptionContext);
    destroyCryptoContext(&srtcpEncryptionContext);
    destroyCryptoContext(&srtcpDecryptionContext);
    memset(&srtpSessionKeys, 0, sizeof(srtpSessionKeys));
    Limelog("Microphone uplink stopped\n");
}

void LiStopMicrophoneUplink(void) {
    stopMicrophoneStream();
}

bool isMicrophoneRtcpPacket(const uint8_t* data, int length) {
    return data != NULL &&
           length >= RTCP_HEADER_LENGTH + SRTP_AEAD_TAG_LENGTH + (int)sizeof(uint32_t) &&
           (data[0] >> 6) == 2 &&
           data[1] >= 192 && data[1] <= 223;
}

void processMicrophoneRtcpPacket(const uint8_t* data, int length) {
    uint8_t aad[RTCP_HEADER_LENGTH + sizeof(uint32_t)];
    uint8_t tagAndCiphertext[SRTP_AEAD_TAG_LENGTH + 256];
    uint8_t plaintext[256];
    uint8_t iv[SRTP_AEAD_SALT_LENGTH];
    uint32_t wireIndex;
    uint32_t index;
    uint32_t senderSsrc;
    int ciphertextLength;
    int plaintextLength = 0;
    int reportCount;

    if (!isMicrophoneRtcpPacket(data, length) ||
        length > (int)(sizeof(plaintext) + RTCP_HEADER_LENGTH +
                       SRTP_AEAD_TAG_LENGTH + sizeof(uint32_t))) {
        return;
    }

    PltLockMutex(&microphoneStateMutex);
    if (!microphoneActive || data[1] != 201) {
        PltUnlockMutex(&microphoneStateMutex);
        return;
    }

    wireIndex = readBe32(data + length - sizeof(uint32_t));
    if ((wireIndex & 0x80000000U) == 0) {
        PltUnlockMutex(&microphoneStateMutex);
        return;
    }
    index = wireIndex & 0x7FFFFFFFU;
    if (hasReceivedSrtcp && index <= lastReceivedSrtcpIndex) {
        PltUnlockMutex(&microphoneStateMutex);
        return;
    }

    ciphertextLength = length - RTCP_HEADER_LENGTH -
                       SRTP_AEAD_TAG_LENGTH - sizeof(uint32_t);
    memcpy(aad, data, RTCP_HEADER_LENGTH);
    memcpy(aad + RTCP_HEADER_LENGTH,
           data + length - sizeof(uint32_t), sizeof(uint32_t));

    // Convert RFC wire layout [ciphertext][tag] to the crypto backend's
    // historical [tag][ciphertext] layout.
    memcpy(tagAndCiphertext,
           data + RTCP_HEADER_LENGTH + ciphertextLength,
           SRTP_AEAD_TAG_LENGTH);
    memcpy(tagAndCiphertext + SRTP_AEAD_TAG_LENGTH,
           data + RTCP_HEADER_LENGTH,
           ciphertextLength);

    senderSsrc = readBe32(data + 4);
    SrtpCreateRtcpAeadIv(srtpSessionKeys.rtcpSalt, senderSsrc, index, iv);
    if (!PltDecryptMessageEx(srtcpDecryptionContext, ALGORITHM_AES_GCM, 0,
                             srtpSessionKeys.rtcpKey, sizeof(srtpSessionKeys.rtcpKey),
                             iv, sizeof(iv),
                             aad, sizeof(aad),
                             tagAndCiphertext, SRTP_AEAD_TAG_LENGTH,
                             tagAndCiphertext + SRTP_AEAD_TAG_LENGTH, ciphertextLength,
                             plaintext, &plaintextLength)) {
        PltUnlockMutex(&microphoneStateMutex);
        return;
    }

    reportCount = data[0] & 0x1F;
    if (reportCount > 0 && plaintextLength >= 24 &&
        readBe32(plaintext) == microphoneSsrc) {
        int32_t cumulativeLost = ((int32_t)plaintext[5] << 16) |
                                 ((int32_t)plaintext[6] << 8) |
                                 plaintext[7];
        if (cumulativeLost & 0x00800000) {
            cumulativeLost |= (int32_t)0xFF000000;
        }

        microphoneStats.fractionLost = plaintext[4];
        microphoneStats.cumulativePacketsLost = cumulativeLost;
        microphoneStats.extendedHighestSequenceNumber = readBe32(plaintext + 8);
        microphoneStats.interarrivalJitter = readBe32(plaintext + 12);
        microphoneStats.lastReceiverReportTimeMs = PltGetMillis();
    }

    lastReceivedSrtcpIndex = index;
    hasReceivedSrtcp = true;
    PltUnlockMutex(&microphoneStateMutex);
}

const MICROPHONE_UPLINK_STATS* LiGetMicrophoneUplinkStats(void) {
    return &microphoneStats;
}

int LiGetMicrophoneUplinkPacketLossPercent(void) {
    int lossPercent;

    if (!microphoneStateMutexInitialized) {
        return 0;
    }

    PltLockMutex(&microphoneStateMutex);
    lossPercent = (microphoneStats.fractionLost * 100 + 128) / 256;
    PltUnlockMutex(&microphoneStateMutex);
    return lossPercent;
}
