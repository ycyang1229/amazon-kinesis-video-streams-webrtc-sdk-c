#include "Samples.h"

// gstreamere related.
#include <gst/gst.h>
#include <gst/app/gstappsink.h>
#include <gst/sdp/gstsdpmessage.h>
#include <gst/gststructure.h>
#include <gst/gstcaps.h>
#include <gst/rtsp/rtsp.h>

extern PSampleConfiguration gSampleConfiguration;

#define GST_STRUCT_FIELD_MEDIA         "media"
#define GST_STRUCT_FIELD_MEDIA_VIDEO   "video"
#define GST_STRUCT_FIELD_MEDIA_AUDIO   "audio"
#define GST_STRUCT_FIELD_ENCODING      "encoding-name"
#define GST_STRUCT_FIELD_PKT_MODE      "packetization-mode"
#define GST_STRUCT_FIELD_PROFILE_LV_ID "profile-level-id"
#define GST_STRUCT_FIELD_ENCODING_H264 "H264"
#define GST_STRUCT_FIELD_ENCODING_VP8  "VP8"
#define GST_STRUCT_FIELD_ENCODING_PCMU "PCMU"
#define GST_STRUCT_FIELD_ENCODING_PCMA "PCMA"
#define GST_STRUCT_FIELD_ENCODING_OPUS "opus"
#define GST_STRUCT_FIELD_ENCODING_G722 "G722"

#define GST_STRUCT_FIELD_PAYLOAD_TYPE "payload"
#define GST_STRUCT_FIELD_CLOCK_RATE   "clock-rate"

// #define VERBOSE
/**
 * @brief quitting the main loop of gstreamer.
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
STATUS gstreamerCloseRtspsrc(PSampleConfiguration pSampleConfiguration)
{
    STATUS retStatus = STATUS_SUCCESS;
    DLOGD("terminating rtsp src.");
    MUTEX_LOCK(pSampleConfiguration->codecConfLock);
    PCodecConfiguration pGstConfiguration = &pSampleConfiguration->codecConfiguration;
    if (pGstConfiguration->mainLoop != NULL) {
        g_main_loop_quit(pGstConfiguration->mainLoop);
    }
    MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    return retStatus;
}

GstFlowReturn on_new_sample(GstElement* sink, gpointer udata, UINT64 trackid)
{
    GstBuffer* buffer;
    BOOL isDroppable, delta;
    GstFlowReturn ret = GST_FLOW_OK;
    GstSample* sample = NULL;
    GstMapInfo info;
    GstSegment* segment;
    GstClockTime buf_pts;
    Frame frame;
    STATUS status;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) udata;
    PCodecConfiguration pGstConfiguration = &pSampleConfiguration->codecConfiguration;

    PSampleStreamingSession pSampleStreamingSession = NULL;
    PRtcRtpTransceiver pRtcRtpTransceiver = NULL;
    UINT32 i;

    if (pSampleConfiguration == NULL) {
        printf("[KVS GStreamer Master] on_new_sample(): operation returned status code: 0x%08x \n", STATUS_NULL_ARG);
        goto CleanUp;
    }

    info.data = NULL;
    sample = gst_app_sink_pull_sample(GST_APP_SINK(sink));
    buffer = gst_sample_get_buffer(sample);
    isDroppable = GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_CORRUPTED) || //!< the buffer data is corrupted.
        GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DECODE_ONLY) || (GST_BUFFER_FLAGS(buffer) == GST_BUFFER_FLAG_DISCONT) ||
        (GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DISCONT) && GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT)) ||
        // drop if buffer contains header only and has invalid timestamp
        !GST_BUFFER_PTS_IS_VALID(buffer);

    if (!isDroppable) {
        delta = GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT);

        frame.flags = delta ? FRAME_FLAG_NONE : FRAME_FLAG_KEY_FRAME;
        segment = gst_sample_get_segment(sample);
        buf_pts = gst_segment_to_running_time(segment, GST_FORMAT_TIME, buffer->pts);
        if (!GST_CLOCK_TIME_IS_VALID(buf_pts)) {
            printf("[KVS GStreamer Master] Frame contains invalid PTS dropping the frame. \n");
        }
        if (!(gst_buffer_map(buffer, &info, GST_MAP_READ))) {
            printf("[KVS GStreamer Master] on_new_sample(): Gst buffer mapping failed\n");
            goto CleanUp;
        }
        frame.trackId = trackid;
        frame.duration = 0;
        frame.version = FRAME_CURRENT_VERSION;
        frame.size = (UINT32) info.size;
        frame.frameData = (PBYTE) info.data;

        MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);
        for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
            pSampleStreamingSession = pSampleConfiguration->sampleStreamingSessionList[i];
            if (pSampleStreamingSession->firstKeyFrame == FALSE && frame.flags != FRAME_FLAG_KEY_FRAME) {
                continue;
            } else {
                pSampleStreamingSession->firstKeyFrame = TRUE;
            }
            frame.index = (UINT32) ATOMIC_INCREMENT(&pSampleStreamingSession->frameIndex);

            if (trackid == DEFAULT_AUDIO_TRACK_ID) {
                pRtcRtpTransceiver = pSampleStreamingSession->pAudioRtcRtpTransceiver;
                frame.presentationTs = buf_pts * DEFAULT_TIME_UNIT_IN_NANOS;
                frame.decodingTs = frame.presentationTs;
            } else {
                pRtcRtpTransceiver = pSampleStreamingSession->pVideoRtcRtpTransceiver;
                frame.presentationTs = buf_pts * DEFAULT_TIME_UNIT_IN_NANOS;
                frame.decodingTs = frame.presentationTs;
            }
            status = writeFrame(pRtcRtpTransceiver, &frame);
            if (status != STATUS_SRTP_NOT_READY_YET && status != STATUS_SUCCESS) {
#ifdef VERBOSE
                printf("writeFrame() failed with 0x%08x", status);
#endif
            }
        }
        MUTEX_UNLOCK(pSampleConfiguration->streamingSessionListReadLock);
    }

CleanUp:

    if (info.data != NULL) {
        gst_buffer_unmap(buffer, &info);
    }

    if (sample != NULL) {
        gst_sample_unref(sample);
    }
    if (ATOMIC_LOAD_BOOL(&pSampleConfiguration->appTerminateFlag) || ATOMIC_LOAD_BOOL(&pSampleConfiguration->terminateCodecFlag)) {
        gstreamerCloseRtspsrc(pSampleConfiguration);
        ret = GST_FLOW_EOS;
    }
    return ret;
}

GstFlowReturn on_new_sample_video(GstElement* sink, gpointer udata)
{
    return on_new_sample(sink, udata, DEFAULT_VIDEO_TRACK_ID);
}

GstFlowReturn on_new_sample_audio(GstElement* sink, gpointer udata)
{
    return on_new_sample(sink, udata, DEFAULT_AUDIO_TRACK_ID);
}

/**
 * @brief the dummy sink for the output of rtspsrc.
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
STATUS gstreamerDummySink(PSampleConfiguration pSampleConfiguration, GstElement** ppDummySink, PCHAR name)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHAR elementName[GST_ELEMENT_NAME_MAX_LEN];
    GstElement* pipeline = NULL;
    GstElement* dummySink = NULL;
    BOOL locked = FALSE;

    MUTEX_LOCK(pSampleConfiguration->codecConfLock);
    locked = TRUE;
    pipeline = (GstElement*) pSampleConfiguration->codecConfiguration.pipeline;
    CHK(pipeline != NULL, STATUS_GST_DUMMY_SINK);
    SNPRINTF(elementName, GST_ELEMENT_NAME_MAX_LEN, "dummySink%s", name);
    dummySink = gst_element_factory_make("fakesink", elementName);
    CHK(dummySink != NULL, STATUS_GST_DUMMY_SINK);
    gst_bin_add_many(GST_BIN(pipeline), dummySink, NULL);

    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    *ppDummySink = dummySink;
    return retStatus;
CleanUp:
    // release the resource when we fail to create the pipeline.
    gst_caps_unref(dummySink);
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    *ppDummySink = NULL;
    return retStatus;
}

/**
 * @brief the video sink for the output of rtspsrc.
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
STATUS gstreamerVideoSink(PSampleConfiguration pSampleConfiguration, GstElement** ppVideoQueue, PCHAR name)
{
    STATUS retStatus = STATUS_SUCCESS;
    PCodecStreamConf pCodecStreamConf;
    GstElement* pipeline;
    CHAR elementName[GST_ELEMENT_NAME_MAX_LEN];
    GstElement* videoQueue = NULL;
    GstElement *videoDepay = NULL, *videoFilter = NULL, *videoAppSink = NULL;
    GstCaps* videoCaps = NULL;
    BOOL locked = FALSE;

    MUTEX_LOCK(pSampleConfiguration->codecConfLock);
    locked = TRUE;

    pCodecStreamConf = &pSampleConfiguration->codecConfiguration.videoStream;
    pipeline = (GstElement*) pSampleConfiguration->codecConfiguration.pipeline;
    CHK(pCodecStreamConf != NULL && pipeline != NULL, STATUS_GST_VIDEO_ELEMENT);

    SNPRINTF(elementName, GST_ELEMENT_NAME_MAX_LEN, "videoQueue%s", name);
    videoQueue = gst_element_factory_make("queue", elementName);
    if (pCodecStreamConf->codec == RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_MODE) {
        videoDepay = gst_element_factory_make("rtph264depay", "videoDepay");
        videoCaps = gst_caps_new_simple("video/x-h264", "stream-format", G_TYPE_STRING, "byte-stream", "alignment", G_TYPE_STRING, "au", NULL);
    } else if (pCodecStreamConf->codec == RTC_CODEC_VP8) {
        videoDepay = gst_element_factory_make("rtpvp8depay", "videoDepay");
        videoCaps = gst_caps_new_simple("video/x-vp8", "profile", G_TYPE_STRING, "0", NULL);
    } else {
        DLOGE("unsupported video type");
        CHK(FALSE, STATUS_GST_UNSUPPORTED_AUDIO);
    }
    CHK(videoCaps != NULL, STATUS_GST_VIDEO_ELEMENT);

    videoFilter = gst_element_factory_make("capsfilter", "videoFilter");
    videoAppSink = gst_element_factory_make("appsink", "videoAppSink");

    CHK(videoQueue != NULL, STATUS_GST_VIDEO_ELEMENT);
    CHK(videoDepay != NULL && videoFilter != NULL && videoAppSink != NULL, STATUS_GST_VIDEO_ELEMENT);

    g_object_set(G_OBJECT(videoFilter), "caps", videoCaps, NULL);
    gst_caps_unref(videoCaps);
    videoCaps = NULL;
    // configure appsink
    g_object_set(G_OBJECT(videoAppSink), "emit-signals", TRUE, "sync", FALSE, NULL);
    g_signal_connect(videoAppSink, "new-sample", G_CALLBACK(on_new_sample_video), pSampleConfiguration);
    // link all the elements.
    gst_bin_add_many(GST_BIN(pipeline), videoQueue, videoDepay, videoFilter, videoAppSink, NULL);
    CHK(gst_element_link_many(videoQueue, videoDepay, videoFilter, videoAppSink, NULL), STATUS_GST_VIDEO_ELEMENT);
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    *ppVideoQueue = videoQueue;
    return retStatus;
CleanUp:
    // release the resource when we fail to create the pipeline.
    gst_object_unref(videoQueue);
    gst_object_unref(videoDepay);
    gst_object_unref(videoCaps);
    gst_object_unref(videoFilter);
    gst_object_unref(videoAppSink);
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    *ppVideoQueue = NULL;
    return retStatus;
}

/**
 * @brief the audio sink for the output of rtspsrc.
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
STATUS gstreamerAudioSink(PSampleConfiguration pSampleConfiguration, GstElement** ppAudioQueue, PCHAR name)
{
    STATUS retStatus = STATUS_SUCCESS;
    PCodecStreamConf pCodecStreamConf;
    CHAR elementName[GST_ELEMENT_NAME_MAX_LEN];
    GstElement* pipeline;
    GstElement* audioQueue = NULL;
    GstElement *audioDepay = NULL, *audioFilter = NULL, *audioAppSink = NULL;
    GstCaps* audioCaps = NULL;
    BOOL locked = FALSE;

    MUTEX_LOCK(pSampleConfiguration->codecConfLock);
    locked = TRUE;

    pCodecStreamConf = &pSampleConfiguration->codecConfiguration.audioStream;
    pipeline = (GstElement*) pSampleConfiguration->codecConfiguration.pipeline;
    CHK(pCodecStreamConf != NULL && pipeline != NULL, STATUS_GST_VIDEO_ELEMENT);

    SNPRINTF(elementName, GST_ELEMENT_NAME_MAX_LEN, "audioQueue%s", name);
    audioQueue = gst_element_factory_make("queue", "audioQueue");
    if (pCodecStreamConf->codec == RTC_CODEC_OPUS) {
        audioDepay = gst_element_factory_make("rtpopusdepay", "audioDepay");
        audioCaps = gst_caps_new_simple("audio/x-opus", "rate", G_TYPE_INT, 48000, "channels", G_TYPE_INT, 2, NULL);
    } else if (pCodecStreamConf->codec == RTC_CODEC_MULAW) {
        audioDepay = gst_element_factory_make("rtppcmudepay", "audioDepay");
        audioCaps = gst_caps_new_simple("audio/x-mulaw", "rate", G_TYPE_INT, 8000, "channels", G_TYPE_INT, 1, NULL);
    } else if (pCodecStreamConf->codec == RTC_CODEC_ALAW) {
        audioDepay = gst_element_factory_make("rtppcmadepay", "audioDepay");
        audioCaps = gst_caps_new_simple("audio/x-alaw", "rate", G_TYPE_INT, 8000, "channels", G_TYPE_INT, 1, NULL);
    } else {
        DLOGE("unsupported audio type");
        CHK(FALSE, STATUS_GST_UNSUPPORTED_AUDIO);
    }
    CHK(audioCaps != NULL, STATUS_GST_AUDIO_ELEMENT);

    audioFilter = gst_element_factory_make("capsfilter", "audioFilter");
    audioAppSink = gst_element_factory_make("appsink", "audioAppSink");

    CHK(audioQueue != NULL, STATUS_GST_AUDIO_ELEMENT);
    CHK(audioDepay != NULL && audioFilter != NULL && audioAppSink != NULL, STATUS_GST_AUDIO_ELEMENT);

    g_object_set(G_OBJECT(audioFilter), "caps", audioCaps, NULL);
    gst_caps_unref(audioCaps);
    audioCaps = NULL;

    g_object_set(G_OBJECT(audioAppSink), "emit-signals", TRUE, "sync", FALSE, NULL);
    g_signal_connect(audioAppSink, "new-sample", G_CALLBACK(on_new_sample_audio), pSampleConfiguration);
    gst_bin_add_many(GST_BIN(pipeline), audioQueue, audioDepay, audioFilter, audioAppSink, NULL);
    CHK(gst_element_link_many(audioQueue, audioDepay, audioFilter, audioAppSink, NULL), STATUS_GST_AUDIO_ELEMENT);
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    *ppAudioQueue = audioQueue;
    return retStatus;
CleanUp:
    // release the resource when we fail to create the pipeline.
    gst_object_unref(audioQueue);
    gst_object_unref(audioDepay);
    gst_object_unref(audioFilter);
    gst_object_unref(audioAppSink);
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    *ppAudioQueue = NULL;
    return retStatus;
}

/**
 * @brief
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
static void rtspsrcOnSdpProbe(GstElement* rtspsrc, GstSDPMessage* sdp, gpointer udata)
{
    guint i;
    gchar* sdpString = gst_sdp_message_as_text(sdp);
    guint mediaNum = gst_sdp_message_medias_len(sdp);
    DLOGD("SDP from RTSP:%s", sdpString);
    DLOGD("mediaNum:%d", mediaNum);

    for (i = 0; i < mediaNum; i++) {
        const GstSDPMedia* sdpMedia = gst_sdp_message_get_media(sdp, i);
        gchar* mediaText = gst_sdp_media_as_text(sdpMedia);
        DLOGD("media text:%s", mediaText);
        g_free(mediaText);
    }
    g_free(sdpString);
}

/**
 * @brief   the callback is invoked when there is no coming.
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
static void rtspsrcOnPadAddedProbe(GstElement* element, GstPad* pad, gpointer udata)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) udata;
    PCodecConfiguration pGstConfiguration = &pSampleConfiguration->codecConfiguration;
    PCodecStreamConf pCodecStreamConf = NULL;
    BOOL video = FALSE;
    BOOL audio = FALSE;
    // gstreamer
    GstElement* pipeline = (GstElement*) pGstConfiguration->pipeline;
    gchar* srcPadName = NULL;
    GstCaps* srcPadTemplateCaps = NULL;
    GstCaps* srcPadCurrentCaps = NULL;
    GstStructure* srcPadStructure = NULL;
    GstElement* nextElement = NULL;
    gchar* media = NULL;
    GstCaps* audioCaps = NULL;
    guint curCapsNum;
    BOOL locked = FALSE;

    srcPadName = gst_pad_get_name(pad);
    srcPadTemplateCaps = gst_pad_get_pad_template_caps(pad);
    DLOGD("A new pad template %s was created", srcPadName);
    srcPadCurrentCaps = gst_pad_get_current_caps(pad);
    curCapsNum = gst_caps_get_size(srcPadCurrentCaps);

    MUTEX_LOCK(pSampleConfiguration->codecConfLock);
    locked = TRUE;
    for (guint i = 0; i < curCapsNum; i++) {
        srcPadStructure = gst_caps_get_structure(srcPadCurrentCaps, i);

        if (gst_structure_has_field(srcPadStructure, GST_STRUCT_FIELD_MEDIA) == TRUE &&
            gst_structure_has_field(srcPadStructure, GST_STRUCT_FIELD_ENCODING) == TRUE) {
            media = gst_structure_get_string(srcPadStructure, GST_STRUCT_FIELD_MEDIA);
            const gchar* encoding_name = gst_structure_get_string(srcPadStructure, GST_STRUCT_FIELD_ENCODING);
            DLOGD("media:%s, encoding_name:%s", media, encoding_name);

            if (STRCMP(media, GST_STRUCT_FIELD_MEDIA_VIDEO) == 0) {
                video = TRUE;
                pCodecStreamConf = &pGstConfiguration->videoStream;
                pCodecStreamConf->codec = -1;
                // h264
                if (STRCMP(encoding_name, GST_STRUCT_FIELD_ENCODING_H264) == 0) {
                    pCodecStreamConf->codec = RTC_CODEC_H264_PROFILE_42E01F_LEVEL_ASYMMETRY_ALLOWED_PACKETIZATION_MODE;
                    // vp8
                } else if (STRCMP(encoding_name, GST_STRUCT_FIELD_ENCODING_VP8) == 0) {
                    pCodecStreamConf->codec = RTC_CODEC_VP8;
                    // others
                } else {
                    DLOGW("unsupported video format");
                }
            } else if (STRCMP(media, GST_STRUCT_FIELD_MEDIA_AUDIO) == 0) {
                audio = TRUE;
                pCodecStreamConf = &pGstConfiguration->audioStream;
                pCodecStreamConf->codec = -1;
                if (STRCMP(encoding_name, GST_STRUCT_FIELD_ENCODING_PCMU) == 0) {
                    pCodecStreamConf->codec = RTC_CODEC_MULAW;
                } else if (STRCMP(encoding_name, GST_STRUCT_FIELD_ENCODING_PCMA) == 0) {
                    pCodecStreamConf->codec = RTC_CODEC_ALAW;
                } else if (STRCMP(encoding_name, GST_STRUCT_FIELD_ENCODING_OPUS) == 0) {
                    pCodecStreamConf->codec = RTC_CODEC_OPUS;
                } else {
                    DLOGW("unsupported audio format");
                }
            }
            DLOGD("codec:%d", pCodecStreamConf->codec);
        }

        if (gst_structure_has_field(srcPadStructure, GST_STRUCT_FIELD_PAYLOAD_TYPE) == TRUE) {
            gint payloadType;
            gst_structure_get_int(srcPadStructure, GST_STRUCT_FIELD_PAYLOAD_TYPE, &payloadType);
            DLOGD("payload:%d", payloadType);
            pCodecStreamConf->payloadType = payloadType;
        }
        if (gst_structure_has_field(srcPadStructure, GST_STRUCT_FIELD_CLOCK_RATE) == TRUE) {
            gint clock_rate;
            gst_structure_get_int(srcPadStructure, GST_STRUCT_FIELD_CLOCK_RATE, &clock_rate);
            DLOGD("clock-rate:%d", clock_rate);
            pCodecStreamConf->clockRate = clock_rate;
        }
    }
    gst_caps_unref(srcPadCurrentCaps);
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    CHK_STATUS(gstreamerDummySink(pSampleConfiguration, &nextElement, media));
    CHK(nextElement != NULL, STATUS_GST_EMPTY_ELEMENT);
    CHK(gst_element_link_filtered(element, nextElement, srcPadTemplateCaps) == TRUE, STATUS_GST_LINK_ELEMENT);
CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    g_free(srcPadName);
    gst_caps_unref(srcPadTemplateCaps);
    CHK_LOG_ERR(retStatus);
    if (retStatus != STATUS_SUCCESS) {
        gstreamerCloseRtspsrc(pSampleConfiguration);
    }
}

/**
 * @brief   the callback is invoked when there is no coming.
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
static void rtspsrcOnNoMorePadsProbe(GstElement* element, gpointer udata)
{
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) udata;
    ATOMIC_STORE_BOOL(&pSampleConfiguration->codecConfigLatched, TRUE);
    gstreamerCloseRtspsrc(pSampleConfiguration);
}

/**
 * @brief   the callback is invoked when a new pad is coming.
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
static void rtspsrcOnPadAdded(GstElement* element, GstPad* pad, gpointer udata)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) udata;
    PCodecConfiguration pGstConfiguration = &pSampleConfiguration->codecConfiguration;
    PCodecStreamConf pCodecStreamConf = NULL;
    GstElement* pipeline = (GstElement*) pGstConfiguration->pipeline;
    gchar* srcPadName = NULL;
    GstCaps* srcPadTemplateCaps = NULL;
    GstCaps* srcPadCurrentCaps = NULL;
    GstStructure* srcPadStructure = NULL;
    GstElement* nextElement = NULL;
    gint payloadType = 0;
    BOOL video = FALSE;
    BOOL audio = FALSE;
    BOOL locked = FALSE;

    MUTEX_LOCK(pSampleConfiguration->codecConfLock);
    locked = TRUE;
    srcPadName = gst_pad_get_name(pad);
    srcPadTemplateCaps = gst_pad_get_pad_template_caps(pad);
    DLOGD("A new pad template %s was created", srcPadName);

    srcPadCurrentCaps = gst_pad_get_current_caps(pad);
    guint curCapsNum = gst_caps_get_size(srcPadCurrentCaps);

    for (guint i = 0; i < curCapsNum; i++) {
        srcPadStructure = gst_caps_get_structure(srcPadCurrentCaps, i);
        if (gst_structure_has_field(srcPadStructure, GST_STRUCT_FIELD_MEDIA) == TRUE) {
            const gchar* media_value = gst_structure_get_string(srcPadStructure, GST_STRUCT_FIELD_MEDIA);
            DLOGD("media_value:%s", media_value);
            if (STRCMP(media_value, GST_STRUCT_FIELD_MEDIA_VIDEO) == 0) {
                video = TRUE;
                pCodecStreamConf = &pGstConfiguration->videoStream;
            } else if (STRCMP(media_value, GST_STRUCT_FIELD_MEDIA_AUDIO) == 0) {
                audio = TRUE;
                pCodecStreamConf = &pGstConfiguration->audioStream;
            }
        }
        if (gst_structure_has_field(srcPadStructure, GST_STRUCT_FIELD_PAYLOAD_TYPE) == TRUE) {
            gst_structure_get_int(srcPadStructure, GST_STRUCT_FIELD_PAYLOAD_TYPE, &payloadType);
            DLOGD("payload:%d", payloadType);
        }
    }
    gst_caps_unref(srcPadCurrentCaps);
    if (pCodecStreamConf != NULL && pCodecStreamConf->payloadType != payloadType) {
        DLOGW("payload type conflict");
    }
    if (video == TRUE && pCodecStreamConf->payloadType == payloadType) {
        DLOGD("connecting video sink");
        CHK_STATUS(gstreamerVideoSink(pSampleConfiguration, &nextElement, srcPadName));
    } else if (audio == TRUE && pCodecStreamConf->payloadType == payloadType) {
        DLOGD("connecting audio sink");
        CHK_STATUS(gstreamerAudioSink(pSampleConfiguration, &nextElement, srcPadName));
    } else {
        DLOGW("connecting dummy sink");
        CHK_STATUS(gstreamerDummySink(pSampleConfiguration, &nextElement, srcPadName));
    }
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    CHK(nextElement != NULL, STATUS_GST_EMPTY_ELEMENT);
    CHK(gst_element_link_filtered(element, nextElement, srcPadTemplateCaps) == TRUE, STATUS_GST_LINK_ELEMENT);
    gst_element_set_state(pipeline, GST_STATE_PLAYING);
CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    g_free(srcPadName);
    gst_caps_unref(srcPadTemplateCaps);
    CHK_LOG_ERR(retStatus);
    if (retStatus != STATUS_SUCCESS) {
        gstreamerCloseRtspsrc(pSampleConfiguration);
    }
}

/**
 * @brief this callback is invoked when pad is removed
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
static void rtspsrcOnPadRemoved(GstElement* element, GstPad* pad, gpointer udata)
{
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) udata;
    gstreamerCloseRtspsrc(pSampleConfiguration);
}

/**
 * @brief the callback is invoked when the error happens on the bus.
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
/* This function is called when an error message is posted on the bus */
static void busMsgErrorCallback(GstBus* bus, GstMessage* msg, gpointer* udata)
{
    GError* err;
    gchar* debug_info;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) udata;
    gst_message_parse_error(msg, &err, &debug_info);
    DLOGE("err code: %d: %d", err->code, GST_RTSP_EINVAL);
    DLOGE("Error received from element %s: %s\n", GST_OBJECT_NAME(msg->src), err->message);
    DLOGE("Debugging information: %s\n", debug_info ? debug_info : "none");
    g_clear_error(&err);
    g_free(debug_info);
    gstreamerCloseRtspsrc(pSampleConfiguration);
}

/**
 * @brief the callback is invoked when the end of stream happens on the bus.
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
static void busMsgEosCallback(GstBus* bus, GstMessage* msg, gpointer* udata)
{
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) udata;
    gstreamerCloseRtspsrc(pSampleConfiguration);
    return;
}

/**
 * @brief the initialization of rtspsrc.
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
STATUS gstreamerRtspsrcInit(PSampleConfiguration pSampleConfiguration, GstElement* pipeline, BOOL enableProbe)
{
    PRtspCameraConfiguration pRtspCameraConfiguration = NULL;
    STATUS retStatus = STATUS_SUCCESS;
    GstElement* rtspSource = NULL;
    BOOL locked = FALSE;

    MUTEX_LOCK(pSampleConfiguration->codecConfLock);
    locked = TRUE;
    rtspSource = gst_element_factory_make("rtspsrc", "rtspSource");
    CHK(pipeline != NULL && rtspSource != NULL, STATUS_NULL_ARG);
    // configure rtspsrc
    pRtspCameraConfiguration = &pSampleConfiguration->rtspCameraConfiguration;
    DLOGD("RTSP URL:%s", pRtspCameraConfiguration->uri);
    g_object_set(G_OBJECT(rtspSource), "location", pRtspCameraConfiguration->uri, "short-header", TRUE, NULL);
    g_object_set(G_OBJECT(rtspSource), "ntp-sync", TRUE, NULL);

    if (pRtspCameraConfiguration->username[0] != '\0' && pRtspCameraConfiguration->password[0] != '\0') {
        g_object_set(G_OBJECT(rtspSource), "user-id", pRtspCameraConfiguration->username, NULL);
        g_object_set(G_OBJECT(rtspSource), "user-pw", pRtspCameraConfiguration->password, NULL);
    }

    // setup the callbacks.
    // g_signal_connect(rtspSource, "pad-added", G_CALLBACK(pad_added_cb), tee);
    if (enableProbe == FALSE) {
        DLOGD("initializing rtspsrc");

        g_signal_connect(G_OBJECT(rtspSource), "pad-added", G_CALLBACK(rtspsrcOnPadAdded), pSampleConfiguration);
        g_signal_connect(G_OBJECT(rtspSource), "pad-removed", G_CALLBACK(rtspsrcOnPadRemoved), pSampleConfiguration);
    } else {
        DLOGD("probing rtspsrc");
        // g_signal_connect(G_OBJECT(rtspSource), "on-sdp", G_CALLBACK(rtspsrcOnSdpProbe), pipeline);
        g_signal_connect(G_OBJECT(rtspSource), "pad-added", G_CALLBACK(rtspsrcOnPadAddedProbe), pSampleConfiguration);
        g_signal_connect(G_OBJECT(rtspSource), "no-more-pads", G_CALLBACK(rtspsrcOnNoMorePadsProbe), pSampleConfiguration);
    }
    gst_bin_add_many(GST_BIN(pipeline), rtspSource, NULL);
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    return retStatus;

CleanUp:

    gst_object_unref(pipeline);
    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->codecConfLock);
    }
    return retStatus;
}

PVOID sendGstreamerProbe(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    PCodecConfiguration pGstConfiguration = &pSampleConfiguration->codecConfiguration;
    GstElement* pipeline = NULL;
    GstBus* bus = NULL;
    GstStateChangeReturn gstRetStatus;

    DLOGI("Streaming from rtsp source");
    CHK(pSampleConfiguration != NULL, STATUS_NULL_ARG);
    CHK((pipeline = gst_pipeline_new("kinesis-rtsp-probe")) != NULL, STATUS_NULL_ARG);
    pGstConfiguration->pipeline = pipeline;

    CHK(gstreamerRtspsrcInit(pSampleConfiguration, pipeline, TRUE) == STATUS_SUCCESS, STATUS_NULL_ARG);

    /* Instruct the bus to emit signals for each received message, and connect to the interesting signals */
    CHK((bus = gst_element_get_bus(pipeline)) != NULL, STATUS_NULL_ARG);
    gst_bus_add_signal_watch(bus);
    g_signal_connect(G_OBJECT(bus), "message::error", G_CALLBACK(busMsgErrorCallback), pSampleConfiguration);
    g_signal_connect(G_OBJECT(bus), "message::eos", G_CALLBACK(busMsgEosCallback), NULL);

    /* start streaming */
    CHK(gst_element_set_state(pipeline, GST_STATE_PLAYING) != GST_STATE_CHANGE_FAILURE, STATUS_NULL_ARG);

    pGstConfiguration->mainLoop = g_main_loop_new(NULL, FALSE);
    // start running the main loop, and it is blocking call.
    g_main_loop_run(pGstConfiguration->mainLoop);

CleanUp:

    /* free resources */
    DLOGD("Release the Gstreamer resources.");
    gst_bus_remove_signal_watch(bus);
    gst_element_set_state(pipeline, GST_STATE_NULL);
    gst_object_unref(bus);
    gst_object_unref(pipeline);
    pGstConfiguration->pipeline = NULL;
    g_main_loop_unref(pGstConfiguration->mainLoop);
    pGstConfiguration->mainLoop = NULL;

    return (PVOID) (ULONG_PTR) retStatus;
}

/**
 * @brief the handler of video and audio.
 *          example: "rtspsrc location=%s name=d"
 *             " d. ! queue ! rtph264depay ! h264parse ! video/x-h264,stream-format=byte-stream,alignment=au,profile=baseline ! appsink sync=TRUE
 * emit-signals=TRUE name=appsink-video" " d. ! queue ! rtppcmudepay ! mulawdec ! audioconvert ! audioresample ! opusenc !
 * audio/x-opus,rate=48000,channels=2 ! appsink sync=TRUE emit-signals=TRUE name=appsink-audio"
 *
 * @param[in]
 *
 * @return STATUS code of the execution. STATUS_SUCCESS on success
 */
PVOID sendGstreamerAudioVideo(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    PCodecConfiguration pGstConfiguration = &pSampleConfiguration->codecConfiguration;
    /* init GStreamer */
    GstElement* pipeline = NULL;
    GstBus* bus = NULL;
    GstStateChangeReturn gstRetStatus;
    UINT32 i;

    CHK(pSampleConfiguration != NULL, STATUS_NULL_ARG);

    DLOGI("Streaming from rtsp source");
    CHK((pipeline = gst_pipeline_new("kinesis-rtsp-pipeline")) != NULL, STATUS_NULL_ARG);
    pGstConfiguration->pipeline = pipeline;

    CHK(gstreamerRtspsrcInit(pSampleConfiguration, pipeline, FALSE) == STATUS_SUCCESS, STATUS_NULL_ARG);

    /* Instruct the bus to emit signals for each received message, and connect to the interesting signals */
    CHK((bus = gst_element_get_bus(pipeline)) != NULL, STATUS_NULL_ARG);
    gst_bus_add_signal_watch(bus);
    g_signal_connect(G_OBJECT(bus), "message::error", G_CALLBACK(busMsgErrorCallback), pSampleConfiguration);
    g_signal_connect(G_OBJECT(bus), "message::eos", G_CALLBACK(busMsgEosCallback), pSampleConfiguration);

    /* start streaming */
    CHK(gst_element_set_state(pipeline, GST_STATE_PLAYING) != GST_STATE_CHANGE_FAILURE, STATUS_NULL_ARG);

    pGstConfiguration->mainLoop = g_main_loop_new(NULL, FALSE);
    // start running the main loop, and it is blocking call.
    g_main_loop_run(pGstConfiguration->mainLoop);

CleanUp:
    // close all the streaming session.
    MUTEX_LOCK(pSampleConfiguration->sampleConfigurationObjLock);
    for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
        DLOGD("terminate the streaming session(%d)", i);
        ATOMIC_STORE_BOOL(&pSampleConfiguration->sampleStreamingSessionList[i]->terminateFlag, TRUE);
    }
    MUTEX_UNLOCK(pSampleConfiguration->sampleConfigurationObjLock);
    CVAR_BROADCAST(pSampleConfiguration->cvar);
    /* free resources */
    DLOGD("Release the Gstreamer resources.");
    gst_bus_remove_signal_watch(bus);
    gst_element_set_state(pipeline, GST_STATE_NULL);
    gst_object_unref(bus);
    gst_object_unref(pipeline);
    pGstConfiguration->pipeline = NULL;
    g_main_loop_unref(pGstConfiguration->mainLoop);
    pGstConfiguration->mainLoop = NULL;

    return (PVOID) (ULONG_PTR) retStatus;
}

VOID createStreamingSesstionPreHookFunc(PSampleConfiguration pSampleConfiguration, PSampleStreamingSession pSampleStreamingSession)
{
    if (!ATOMIC_LOAD_BOOL(&pSampleConfiguration->codecConfigLatched)) {
        sendGstreamerProbe(pSampleConfiguration);
    }
}

VOID freeStreamingSesstionPostHookFunc(PSampleConfiguration pSampleConfiguration, PSampleStreamingSession pSampleStreamingSession)
{
    if (pSampleConfiguration->streamingSessionCount == 0) {
        ATOMIC_STORE_BOOL(&pSampleConfiguration->terminateCodecFlag, TRUE);
    }
}

INT32 main(INT32 argc, CHAR* argv[])
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = NULL;
    PCHAR pRtspChannel;

    SET_INSTRUMENTED_ALLOCATORS();

    signal(SIGINT, sigintHandler);

    // do trickle-ice by default
    printf("[KVS GStreamer Master] Using trickleICE by default\n");
    CHK_ERR((pRtspChannel = getenv(RTSP_CHANNEL)) != NULL, STATUS_INVALID_OPERATION, "RTSP_CHANNEL must be set");

    retStatus = createSampleConfiguration(pRtspChannel, SIGNALING_CHANNEL_ROLE_TYPE_MASTER, TRUE, TRUE, &pSampleConfiguration);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS GStreamer Master] createSampleConfiguration(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }

    printf("[KVS GStreamer Master] Created signaling channel %s\n", pRtspChannel);

    if (pSampleConfiguration->enableFileLogging) {
        retStatus =
            createFileLogger(FILE_LOGGING_BUFFER_SIZE, MAX_NUMBER_OF_LOG_FILES, (PCHAR) FILE_LOGGER_LOG_FILE_DIRECTORY_PATH, TRUE, TRUE, NULL);
        if (retStatus != STATUS_SUCCESS) {
            printf("[KVS Master] createFileLogger(): operation returned status code: 0x%08x \n", retStatus);
            pSampleConfiguration->enableFileLogging = FALSE;
        }
    }

    pSampleConfiguration->videoSource = sendGstreamerAudioVideo;
    pSampleConfiguration->mediaType = SAMPLE_STREAMING_AUDIO_VIDEO;
    pSampleConfiguration->onDataChannel = onDataChannel;
    pSampleConfiguration->customData = (UINT64) pSampleConfiguration;
    pSampleConfiguration->useTestSrc = FALSE;
    pSampleConfiguration->createStreamingSessionPreHook = createStreamingSesstionPreHookFunc;
    pSampleConfiguration->freeStreamingSessionPostHook = freeStreamingSesstionPostHookFunc;

    /* Initialize GStreamer */
    gst_init(NULL, NULL);
    sendGstreamerProbe(pSampleConfiguration);
    printf("[KVS Gstreamer Master] Finished initializing GStreamer\n");

    // Initalize KVS WebRTC. This must be done before anything else, and must only be done once.
    retStatus = initKvsWebRtc();
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS GStreamer Master] initKvsWebRtc(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }
    printf("[KVS GStreamer Master] KVS WebRTC initialization completed successfully\n");

    pSampleConfiguration->signalingClientCallbacks.messageReceivedFn = signalingMessageReceived;

    strcpy(pSampleConfiguration->clientInfo.clientId, SAMPLE_MASTER_CLIENT_ID);

    retStatus = createSignalingClientSync(&pSampleConfiguration->clientInfo, &pSampleConfiguration->channelInfo,
                                          &pSampleConfiguration->signalingClientCallbacks, pSampleConfiguration->pCredentialProvider,
                                          &pSampleConfiguration->signalingClientHandle);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS GStreamer Master] createSignalingClientSync(): operation returned status code: 0x%08x \n", retStatus);
    }
    printf("[KVS GStreamer Master] Signaling client created successfully\n");

    // Enable the processing of the messages
    retStatus = signalingClientConnectSync(pSampleConfiguration->signalingClientHandle);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS GStreamer Master] signalingClientConnectSync(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }

    printf("[KVS GStreamer Master] Signaling client connection to socket established\n");
    printf("[KVS Gstreamer Master] Beginning streaming...check the stream over channel %s\n", pRtspChannel);

    gSampleConfiguration = pSampleConfiguration;

    // Checking for termination
    retStatus = sessionCleanupWait(pSampleConfiguration);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS GStreamer Master] sessionCleanupWait(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }

    printf("[KVS GStreamer Master] Streaming session terminated\n");

CleanUp:

    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS GStreamer Master] Terminated with status code 0x%08x", retStatus);
    }

    printf("[KVS GStreamer Master] Cleaning up....\n");

    if (pSampleConfiguration != NULL) {
        // Kick of the termination sequence
        ATOMIC_STORE_BOOL(&pSampleConfiguration->appTerminateFlag, TRUE);

        if (pSampleConfiguration->mediaSenderTid != INVALID_TID_VALUE) {
            THREAD_JOIN(pSampleConfiguration->mediaSenderTid, NULL);
        }

        if (pSampleConfiguration->enableFileLogging) {
            freeFileLogger();
        }
        retStatus = freeSignalingClient(&pSampleConfiguration->signalingClientHandle);
        if (retStatus != STATUS_SUCCESS) {
            printf("[KVS GStreamer Master] freeSignalingClient(): operation returned status code: 0x%08x \n", retStatus);
        }

        retStatus = freeSampleConfiguration(&pSampleConfiguration);
        if (retStatus != STATUS_SUCCESS) {
            printf("[KVS GStreamer Master] freeSampleConfiguration(): operation returned status code: 0x%08x \n", retStatus);
        }
    }
    printf("[KVS Gstreamer Master] Cleanup done\n");

    RESET_INSTRUMENTED_ALLOCATORS();
    // https://www.gnu.org/software/libc/manual/html_node/Exit-Status.html
    // We can only return with 0 - 127. Some platforms treat exit code >= 128
    // to be a success code, which might give an unintended behaviour.
    // Some platforms also treat 1 or 0 differently, so it's better to use
    // EXIT_FAILURE and EXIT_SUCCESS macros for portability.
    return STATUS_FAILED(retStatus) ? EXIT_FAILURE : EXIT_SUCCESS;
}
