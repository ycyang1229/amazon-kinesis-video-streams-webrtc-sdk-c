#define LOG_CLASS "WebRtcSamples"
#include "Samples.h"

PSampleConfiguration gSampleConfiguration = NULL;

VOID sigintHandler(INT32 sigNum)
{
    UNUSED_PARAM(sigNum);
    if (gSampleConfiguration != NULL) {
        ATOMIC_STORE_BOOL(&gSampleConfiguration->interrupted, TRUE);
        CVAR_BROADCAST(gSampleConfiguration->cvar);
    }
}


STATUS signalingClientStateChanged(UINT64 customData, SIGNALING_CLIENT_STATE state)
{
    UNUSED_PARAM(customData);
    STATUS retStatus = STATUS_SUCCESS;
    PCHAR pStateStr;

    signalingClientGetStateString(state, &pStateStr);

    DLOGV("Signaling client state changed to %d - '%s'", state, pStateStr);

    // Return success to continue
    return retStatus;
}

STATUS signalingClientError(UINT64 customData, STATUS status, PCHAR msg, UINT32 msgLen)
{
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) customData;

    DLOGW("Signaling client generated an error 0x%08x - '%.*s'", status, msgLen, msg);

    // We will force re-create the signaling client on the following errors
    if (status == STATUS_SIGNALING_ICE_CONFIG_REFRESH_FAILED || status == STATUS_SIGNALING_RECONNECT_FAILED) {
        ATOMIC_STORE_BOOL(&pSampleConfiguration->recreateSignalingClient, TRUE);
        CVAR_BROADCAST(pSampleConfiguration->cvar);
    }

    return STATUS_SUCCESS;
}



VOID onIceCandidateHandler(UINT64 customData, PCHAR candidateJson)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleStreamingSession pSampleStreamingSession = (PSampleStreamingSession) customData;
    SignalingMessage message;

    CHK(pSampleStreamingSession != NULL, STATUS_NULL_ARG);

    if (candidateJson == NULL) {
        DLOGD("ice candidate gathering finished");
        ATOMIC_STORE_BOOL(&pSampleStreamingSession->candidateGatheringDone, TRUE);
        CVAR_BROADCAST(pSampleStreamingSession->pSampleConfiguration->cvar);
    } else if (pSampleStreamingSession->pSampleConfiguration->trickleIce && ATOMIC_LOAD_BOOL(&pSampleStreamingSession->peerIdReceived)) {
        message.version = SIGNALING_MESSAGE_CURRENT_VERSION;
        message.messageType = SIGNALING_MESSAGE_TYPE_ICE_CANDIDATE;
        STRCPY(message.peerClientId, pSampleStreamingSession->peerId);
        message.payloadLen = (UINT32) STRLEN(candidateJson);
        STRCPY(message.payload, candidateJson);
        message.correlationId[0] = '\0';
        CHK_STATUS(signalingClientSendMessageSync(pSampleStreamingSession->pSampleConfiguration->signalingClientHandle, &message));
    }

CleanUp:

    CHK_LOG_ERR(retStatus);
}


STATUS awaitGetIceConfigInfoCount(SIGNALING_CLIENT_HANDLE signalingClientHandle, PUINT32 pIceConfigInfoCount)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 elapsed = 0;

    CHK(IS_VALID_SIGNALING_CLIENT_HANDLE(signalingClientHandle) && pIceConfigInfoCount != NULL, STATUS_NULL_ARG);

    while (TRUE) {
        // Get the configuration count
        CHK_STATUS(signalingClientGetIceConfigInfoCount(signalingClientHandle, pIceConfigInfoCount));

        // Return OK if we have some ice configs
        CHK(*pIceConfigInfoCount == 0, retStatus);

        // Check for timeout
        CHK_ERR(elapsed <= ASYNC_ICE_CONFIG_INFO_WAIT_TIMEOUT, STATUS_OPERATION_TIMED_OUT, "Couldn't retrieve ICE configurations in alotted time.");

        THREAD_SLEEP(ICE_CONFIG_INFO_POLL_PERIOD);
        elapsed += ICE_CONFIG_INFO_POLL_PERIOD;
    }

CleanUp:

    return retStatus;
}

STATUS createSampleStreamingSession(PSampleConfiguration pSampleConfiguration, PCHAR peerId, BOOL isMaster,
                                    PSampleStreamingSession* ppSampleStreamingSession)
{
    STATUS retStatus = STATUS_SUCCESS;
    RtcMediaStreamTrack videoTrack, audioTrack;
    PSampleStreamingSession pSampleStreamingSession = NULL;

    MEMSET(&videoTrack, 0x00, SIZEOF(RtcMediaStreamTrack));
    MEMSET(&audioTrack, 0x00, SIZEOF(RtcMediaStreamTrack));

    CHK(pSampleConfiguration != NULL && ppSampleStreamingSession != NULL, STATUS_NULL_ARG);
    CHK((isMaster && peerId != NULL) || !isMaster, STATUS_INVALID_ARG);

    pSampleStreamingSession = (PSampleStreamingSession) MEMCALLOC(1, SIZEOF(SampleStreamingSession));
    CHK(pSampleStreamingSession != NULL, STATUS_NOT_ENOUGH_MEMORY);

    if (isMaster) {
        STRCPY(pSampleStreamingSession->peerId, peerId);
    } else {
        STRCPY(pSampleStreamingSession->peerId, SAMPLE_VIEWER_CLIENT_ID);
    }
    ATOMIC_STORE_BOOL(&pSampleStreamingSession->peerIdReceived, TRUE);

    pSampleStreamingSession->pSampleConfiguration = pSampleConfiguration;

    ATOMIC_STORE_BOOL(&pSampleStreamingSession->terminateFlag, FALSE);
    ATOMIC_STORE_BOOL(&pSampleStreamingSession->candidateGatheringDone, FALSE);

CleanUp:

    if (STATUS_FAILED(retStatus) && pSampleStreamingSession != NULL) {
        freeSampleStreamingSession(&pSampleStreamingSession);
        pSampleStreamingSession = NULL;
    }

    if (ppSampleStreamingSession != NULL) {
        *ppSampleStreamingSession = pSampleStreamingSession;
    }

    return retStatus;
}

STATUS freeSampleStreamingSession(PSampleStreamingSession* ppSampleStreamingSession)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleStreamingSession pSampleStreamingSession = NULL;

    CHK(ppSampleStreamingSession != NULL, STATUS_NULL_ARG);
    pSampleStreamingSession = *ppSampleStreamingSession;
    CHK(pSampleStreamingSession != NULL, retStatus);

    DLOGD("Freeing streaming session with peer id: %s ", pSampleStreamingSession->peerId);

    ATOMIC_STORE_BOOL(&pSampleStreamingSession->terminateFlag, TRUE);

    if (pSampleStreamingSession->shutdownCallback != NULL) {
        pSampleStreamingSession->shutdownCallback(pSampleStreamingSession->shutdownCallbackCustomData, pSampleStreamingSession);
    }

    if (IS_VALID_TID_VALUE(pSampleStreamingSession->receiveAudioVideoSenderTid)) {
        THREAD_JOIN(pSampleStreamingSession->receiveAudioVideoSenderTid, NULL);
    }
    SAFE_MEMFREE(pSampleStreamingSession);

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}

STATUS streamingSessionOnShutdown(PSampleStreamingSession pSampleStreamingSession, UINT64 customData,
                                  StreamSessionShutdownCallback streamSessionShutdownCallback)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSampleStreamingSession != NULL && streamSessionShutdownCallback != NULL, STATUS_NULL_ARG);

    pSampleStreamingSession->shutdownCallbackCustomData = customData;
    pSampleStreamingSession->shutdownCallback = streamSessionShutdownCallback;

CleanUp:

    return retStatus;
}

VOID sampleFrameHandler(UINT64 customData, PFrame pFrame)
{
    UNUSED_PARAM(customData);
    DLOGV("Frame received. TrackId: %" PRIu64 ", Size: %u, Flags %u", pFrame->trackId, pFrame->size, pFrame->flags);
}

VOID sampleBandwidthEstimationHandler(UINT64 customData, DOUBLE maxiumBitrate)
{
    UNUSED_PARAM(customData);
    DLOGV("received bitrate suggestion: %f", maxiumBitrate);
}


STATUS traverseDirectoryPEMFileScan(UINT64 customData, DIR_ENTRY_TYPES entryType, PCHAR fullPath, PCHAR fileName)
{
    UNUSED_PARAM(entryType);
    UNUSED_PARAM(fullPath);

    PCHAR certName = (PCHAR) customData;
    UINT32 fileNameLen = STRLEN(fileName);

    if (fileNameLen > ARRAY_SIZE(CA_CERT_PEM_FILE_EXTENSION) + 1 &&
        (STRCMPI(CA_CERT_PEM_FILE_EXTENSION, &fileName[fileNameLen - ARRAY_SIZE(CA_CERT_PEM_FILE_EXTENSION) + 1]) == 0)) {
        certName[0] = FPATHSEPARATOR;
        certName++;
        STRCPY(certName, fileName);
    }

    return STATUS_SUCCESS;
}

STATUS lookForSslCert(PSampleConfiguration* ppSampleConfiguration)
{
    STATUS retStatus = STATUS_SUCCESS;
    struct stat pathStat;
    CHAR certName[MAX_PATH_LEN];
    PSampleConfiguration pSampleConfiguration = *ppSampleConfiguration;

    MEMSET(certName, 0x0, ARRAY_SIZE(certName));
    pSampleConfiguration->pCaCertPath = getenv(CACERT_PATH_ENV_VAR);

    // if ca cert path is not set from the environment, try to use the one that cmake detected
    if (pSampleConfiguration->pCaCertPath == NULL) {
        CHK_ERR(STRNLEN(DEFAULT_KVS_CACERT_PATH, MAX_PATH_LEN) > 0, STATUS_INVALID_OPERATION, "No ca cert path given (error:%s)", strerror(errno));
        pSampleConfiguration->pCaCertPath = DEFAULT_KVS_CACERT_PATH;
    } else {
        // Check if the environment variable is a path
        CHK(0 == FSTAT(pSampleConfiguration->pCaCertPath, &pathStat), STATUS_DIRECTORY_ENTRY_STAT_ERROR);

        if (S_ISDIR(pathStat.st_mode)) {
            CHK_STATUS(traverseDirectory(pSampleConfiguration->pCaCertPath, (UINT64) &certName, /* iterate */ FALSE, traverseDirectoryPEMFileScan));

            if (certName[0] != 0x0) {
                STRCAT(pSampleConfiguration->pCaCertPath, certName);
            } else {
                DLOGW("Cert not found in path set...checking if CMake detected a path\n");
                CHK_ERR(STRNLEN(DEFAULT_KVS_CACERT_PATH, MAX_PATH_LEN) > 0, STATUS_INVALID_OPERATION, "No ca cert path given (error:%s)",
                        strerror(errno));
                DLOGI("CMake detected cert path\n");
                pSampleConfiguration->pCaCertPath = DEFAULT_KVS_CACERT_PATH;
            }
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);
    return retStatus;
}

STATUS createSampleConfiguration(PCHAR channelName, SIGNALING_CHANNEL_ROLE_TYPE roleType, BOOL trickleIce, BOOL useTurn,
                                 PSampleConfiguration* ppSampleConfiguration)
{
    STATUS retStatus = STATUS_SUCCESS;
    PCHAR pAccessKey, pSecretKey, pSessionToken, pLogLevel;
    PSampleConfiguration pSampleConfiguration = NULL;
    UINT32 logLevel;

    CHK(ppSampleConfiguration != NULL, STATUS_NULL_ARG);

    CHK(NULL != (pSampleConfiguration = (PSampleConfiguration) MEMCALLOC(1, SIZEOF(SampleConfiguration))), STATUS_NOT_ENOUGH_MEMORY);

    CHK_ERR((pAccessKey = getenv(ACCESS_KEY_ENV_VAR)) != NULL, STATUS_INVALID_OPERATION, "AWS_ACCESS_KEY_ID must be set");
    CHK_ERR((pSecretKey = getenv(SECRET_KEY_ENV_VAR)) != NULL, STATUS_INVALID_OPERATION, "AWS_SECRET_ACCESS_KEY must be set");
    pSessionToken = getenv(SESSION_TOKEN_ENV_VAR);
    pSampleConfiguration->enableFileLogging = FALSE;
    if (NULL != getenv(ENABLE_FILE_LOGGING)) {
        pSampleConfiguration->enableFileLogging = TRUE;
    }
    if ((pSampleConfiguration->channelInfo.pRegion = getenv(DEFAULT_REGION_ENV_VAR)) == NULL) {
        pSampleConfiguration->channelInfo.pRegion = DEFAULT_AWS_REGION;
    }

    CHK_STATUS(lookForSslCert(&pSampleConfiguration));

    // Set the logger log level
    if (NULL == (pLogLevel = getenv(DEBUG_LOG_LEVEL_ENV_VAR)) || (STATUS_SUCCESS != STRTOUI32(pLogLevel, NULL, 10, &logLevel))) {
        logLevel = LOG_LEVEL_WARN;
    }

    SET_LOGGER_LOG_LEVEL(logLevel);

    CHK_STATUS(
        createStaticCredentialProvider(pAccessKey, 0, pSecretKey, 0, pSessionToken, 0, MAX_UINT64, &pSampleConfiguration->pCredentialProvider));

    pSampleConfiguration->audioSenderTid = INVALID_TID_VALUE;
    pSampleConfiguration->videoSenderTid = INVALID_TID_VALUE;
    pSampleConfiguration->signalingClientHandle = INVALID_SIGNALING_CLIENT_HANDLE_VALUE;
    pSampleConfiguration->sampleConfigurationObjLock = MUTEX_CREATE(TRUE);
    pSampleConfiguration->cvar = CVAR_CREATE();
    /* This is ignored for master. Master can extract the info from offer. Viewer has to know if peer can trickle or
     * not ahead of time. */
    pSampleConfiguration->trickleIce = trickleIce;
    pSampleConfiguration->useTurn = useTurn;

    pSampleConfiguration->channelInfo.version = CHANNEL_INFO_CURRENT_VERSION;
    pSampleConfiguration->channelInfo.pChannelName = channelName;
    pSampleConfiguration->channelInfo.pKmsKeyId = NULL;
    pSampleConfiguration->channelInfo.tagCount = 0;
    pSampleConfiguration->channelInfo.pTags = NULL;
    pSampleConfiguration->channelInfo.channelType = SIGNALING_CHANNEL_TYPE_SINGLE_MASTER;
    pSampleConfiguration->channelInfo.channelRoleType = roleType;
    pSampleConfiguration->channelInfo.cachingPolicy = SIGNALING_API_CALL_CACHE_TYPE_FILE;
    pSampleConfiguration->channelInfo.cachingPeriod = SIGNALING_API_CALL_CACHE_TTL_SENTINEL_VALUE;
    pSampleConfiguration->channelInfo.asyncIceServerConfig = TRUE;
    pSampleConfiguration->channelInfo.retry = TRUE;
    pSampleConfiguration->channelInfo.reconnect = TRUE;
    pSampleConfiguration->channelInfo.pCertPath = pSampleConfiguration->pCaCertPath;
    pSampleConfiguration->channelInfo.messageTtl = 0; // Default is 60 seconds

    pSampleConfiguration->signalingClientCallbacks.version = SIGNALING_CLIENT_CALLBACKS_CURRENT_VERSION;
    pSampleConfiguration->signalingClientCallbacks.errorReportFn = signalingClientError;
    pSampleConfiguration->signalingClientCallbacks.stateChangeFn = signalingClientStateChanged;
    pSampleConfiguration->signalingClientCallbacks.customData = (UINT64) pSampleConfiguration;

    pSampleConfiguration->clientInfo.version = SIGNALING_CLIENT_INFO_CURRENT_VERSION;
    pSampleConfiguration->clientInfo.loggingLevel = logLevel;

    ATOMIC_STORE_BOOL(&pSampleConfiguration->interrupted, FALSE);
    ATOMIC_STORE_BOOL(&pSampleConfiguration->mediaThreadStarted, FALSE);
    ATOMIC_STORE_BOOL(&pSampleConfiguration->appTerminateFlag, FALSE);
    ATOMIC_STORE_BOOL(&pSampleConfiguration->recreateSignalingClient, FALSE);

    pSampleConfiguration->iceUriCount = 0;

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        freeSampleConfiguration(&pSampleConfiguration);
    }

    if (ppSampleConfiguration != NULL) {
        *ppSampleConfiguration = pSampleConfiguration;
    }

    return retStatus;
}

STATUS logSignalingClientStats(PSignalingClientMetrics pSignalingClientMetrics)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    CHK(pSignalingClientMetrics != NULL, STATUS_NULL_ARG);
    DLOGD("Signaling client connection duration: %" PRIu64 " ms",
          (pSignalingClientMetrics->signalingClientStats.connectionDuration / HUNDREDS_OF_NANOS_IN_A_MILLISECOND));
    DLOGD("Number of signaling client API errors: %d", pSignalingClientMetrics->signalingClientStats.numberOfErrors);
    DLOGD("Number of runtime errors in the session: %d", pSignalingClientMetrics->signalingClientStats.numberOfRuntimeErrors);
    DLOGD("Signaling client uptime: %" PRIu64 " ms",
          (pSignalingClientMetrics->signalingClientStats.connectionDuration / HUNDREDS_OF_NANOS_IN_A_MILLISECOND));
    // This gives the EMA of the createChannel, describeChannel, getChannelEndpoint and deleteChannel calls
    DLOGD("Control Plane API call latency: %" PRIu64 " ms",
          (pSignalingClientMetrics->signalingClientStats.cpApiCallLatency / HUNDREDS_OF_NANOS_IN_A_MILLISECOND));
    // This gives the EMA of the getIceConfig() call.
    DLOGD("Data Plane API call latency: %" PRIu64 " ms",
          (pSignalingClientMetrics->signalingClientStats.dpApiCallLatency / HUNDREDS_OF_NANOS_IN_A_MILLISECOND));
CleanUp:
    LEAVES();
    return retStatus;
}
STATUS freeSampleConfiguration(PSampleConfiguration* ppSampleConfiguration)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration;
    UINT32 i;

    CHK(ppSampleConfiguration != NULL, STATUS_NULL_ARG);
    pSampleConfiguration = *ppSampleConfiguration;

    CHK(pSampleConfiguration != NULL, retStatus);
    

    SAFE_MEMFREE(pSampleConfiguration->pVideoFrameBuffer);
    SAFE_MEMFREE(pSampleConfiguration->pAudioFrameBuffer);

    if (IS_VALID_CVAR_VALUE(pSampleConfiguration->cvar) && IS_VALID_MUTEX_VALUE(pSampleConfiguration->sampleConfigurationObjLock)) {
        CVAR_BROADCAST(pSampleConfiguration->cvar);
        // lock to wait until awoken thread finish.
        MUTEX_LOCK(pSampleConfiguration->sampleConfigurationObjLock);
        MUTEX_UNLOCK(pSampleConfiguration->sampleConfigurationObjLock);
    }

    if (IS_VALID_MUTEX_VALUE(pSampleConfiguration->sampleConfigurationObjLock)) {
        MUTEX_FREE(pSampleConfiguration->sampleConfigurationObjLock);
    }

    if (IS_VALID_CVAR_VALUE(pSampleConfiguration->cvar)) {
        CVAR_FREE(pSampleConfiguration->cvar);
    }

    freeStaticCredentialProvider(&pSampleConfiguration->pCredentialProvider);

    MEMFREE(*ppSampleConfiguration);
    *ppSampleConfiguration = NULL;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS sessionCleanupWait(PSampleConfiguration pSampleConfiguration)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSampleStreamingSession pSampleStreamingSession = NULL;
    UINT32 i;
    BOOL locked = FALSE;
    SIGNALING_CLIENT_STATE signalingClientState;

    CHK(pSampleConfiguration != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pSampleConfiguration->sampleConfigurationObjLock);
    locked = TRUE;

    while (!ATOMIC_LOAD_BOOL(&pSampleConfiguration->interrupted)) {
        // scan and cleanup terminated streaming session
        for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
            if (ATOMIC_LOAD_BOOL(&pSampleConfiguration->sampleStreamingSessionList[i]->terminateFlag)) {
                pSampleStreamingSession = pSampleConfiguration->sampleStreamingSessionList[i];

                // swap with last element and decrement count
                pSampleConfiguration->streamingSessionCount--;
                pSampleConfiguration->sampleStreamingSessionList[i] =
                    pSampleConfiguration->sampleStreamingSessionList[pSampleConfiguration->streamingSessionCount];
                CHK_STATUS(freeSampleStreamingSession(&pSampleStreamingSession));
            }
        }

        // periodically wake up and clean up terminated streaming session
        CVAR_WAIT(pSampleConfiguration->cvar, pSampleConfiguration->sampleConfigurationObjLock, 5 * HUNDREDS_OF_NANOS_IN_A_SECOND);

        // Check if we need to re-create the signaling client on-the-fly
        if (ATOMIC_LOAD_BOOL(&pSampleConfiguration->recreateSignalingClient) &&
            STATUS_SUCCEEDED(freeSignalingClient(&pSampleConfiguration->signalingClientHandle)) &&
            STATUS_SUCCEEDED(createSignalingClientSync(&pSampleConfiguration->clientInfo, &pSampleConfiguration->channelInfo,
                                                       &pSampleConfiguration->signalingClientCallbacks, pSampleConfiguration->pCredentialProvider,
                                                       &pSampleConfiguration->signalingClientHandle))) {
            // Re-set the variable again
            ATOMIC_STORE_BOOL(&pSampleConfiguration->recreateSignalingClient, FALSE);
        }

        // Check the signaling client state and connect if needed
        if (IS_VALID_SIGNALING_CLIENT_HANDLE(pSampleConfiguration->signalingClientHandle)) {
            CHK_STATUS(signalingClientGetCurrentState(pSampleConfiguration->signalingClientHandle, &signalingClientState));
            if (signalingClientState == SIGNALING_CLIENT_STATE_READY) {
                UNUSED_PARAM(signalingClientConnectSync(pSampleConfiguration->signalingClientHandle));
            }
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->sampleConfigurationObjLock);
    }

    LEAVES();
    return retStatus;
}
