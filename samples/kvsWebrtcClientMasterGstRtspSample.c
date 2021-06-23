#include "Samples.h"

// gstreamere related.
#include <gst/gst.h>
#include <gst/app/gstappsink.h>
#include <gst/sdp/gstsdpmessage.h>
#include <gst/gststructure.h>
#include <gst/gstcaps.h>
#include <gst/rtsp/rtsp.h>

extern PSampleConfiguration gSampleConfiguration;

// #define VERBOSE
/**
 * @brief   
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
GstFlowReturn on_new_sample(GstElement* sink, gpointer data, UINT64 trackid)
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
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) data;
    PGstConfiguration pGstConfiguration = &pSampleConfiguration->gstConfiguration;

    PSampleStreamingSession pSampleStreamingSession = NULL;
    PRtcRtpTransceiver pRtcRtpTransceiver = NULL;
    UINT32 i;

    if (pSampleConfiguration == NULL) {
        printf("[KVS GStreamer Master] on_new_sample(): operation returned status code: 0x%08x \n", STATUS_NULL_ARG);
        goto CleanUp;
    }

    info.data = NULL;
    // #gst
    // https://gstreamer.freedesktop.org/documentation/applib/gstappsink.html?gi-language=c#gst_app_sink_pull_sample
    sample = gst_app_sink_pull_sample(GST_APP_SINK(sink));
    // #gst
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstsample.html?gi-language=c#gst_sample_get_buffer
    buffer = gst_sample_get_buffer(sample);
    // https://developer.gnome.org/gstreamer/stable/gstreamer-GstBuffer.html
    isDroppable = GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_CORRUPTED) || //!< the buffer data is corrupted.
        GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DECODE_ONLY) || (GST_BUFFER_FLAGS(buffer) == GST_BUFFER_FLAG_DISCONT) ||
        (GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DISCONT) && GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT)) ||
        // drop if buffer contains header only and has invalid timestamp
        !GST_BUFFER_PTS_IS_VALID(buffer);

    if (!isDroppable) {
        delta = GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT);

        frame.flags = delta ? FRAME_FLAG_NONE : FRAME_FLAG_KEY_FRAME;

        // convert from segment timestamp to running time in live mode.
        // # gst
        // https://gstreamer.freedesktop.org/documentation/gstreamer/gstsample.html?gi-language=c#gst_sample_get_segment
        segment = gst_sample_get_segment(sample);
        // https://gstreamer.freedesktop.org/documentation/gstreamer/gstsegment.html?gi-language=c#gst_segment_to_running_time
        buf_pts = gst_segment_to_running_time(segment, GST_FORMAT_TIME, buffer->pts);
        if (!GST_CLOCK_TIME_IS_VALID(buf_pts)) {
            printf("[KVS GStreamer Master] Frame contains invalid PTS dropping the frame. \n");
        }
        // https://gstreamer.freedesktop.org/documentation/gstreamer/gstbuffer.html?gi-language=c#gst_buffer_map
        if (!(gst_buffer_map(buffer, &info, GST_MAP_READ))) {
            printf("[KVS GStreamer Master] on_new_sample(): Gst buffer mapping failed\n");
            goto CleanUp;
        }
        // DLOGD("buf_pts(%d) = %"GST_TIME_FORMAT, trackid, GST_TIME_ARGS (buf_pts));
        frame.trackId = trackid;
        frame.duration = 0;
        frame.version = FRAME_CURRENT_VERSION;
        frame.size = (UINT32) info.size;
        frame.frameData = (PBYTE) info.data;
        // #YC_TBD.
        MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);
        for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
            pSampleStreamingSession = pSampleConfiguration->sampleStreamingSessionList[i];
            frame.index = (UINT32) ATOMIC_INCREMENT(&pSampleStreamingSession->frameIndex);

            if (trackid == DEFAULT_AUDIO_TRACK_ID) {
                pRtcRtpTransceiver = pSampleStreamingSession->pAudioRtcRtpTransceiver;
                frame.presentationTs = buf_pts * DEFAULT_TIME_UNIT_IN_NANOS; // pSampleStreamingSession->audioTimestamp;
                frame.decodingTs = frame.presentationTs;
                pSampleStreamingSession->audioTimestamp +=
                    SAMPLE_AUDIO_FRAME_DURATION; // assume audio frame size is 20ms, which is default in opusenc
            } else {
                pRtcRtpTransceiver = pSampleStreamingSession->pVideoRtcRtpTransceiver;
                frame.presentationTs = buf_pts * DEFAULT_TIME_UNIT_IN_NANOS; // pSampleStreamingSession->videoTimestamp;
                frame.decodingTs = frame.presentationTs;
                pSampleStreamingSession->videoTimestamp += SAMPLE_VIDEO_FRAME_DURATION; // assume video fps is 30
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

    if (ATOMIC_LOAD_BOOL(&pSampleConfiguration->appTerminateFlag) || pSampleConfiguration->streamingSessionCount == 0) {
        DLOGD("There is no streaming sessions, and we start terminating the rtspsrc.");
        if (pGstConfiguration->mainLoop != NULL) {
            g_main_loop_quit(pGstConfiguration->mainLoop);
        }
        ret = GST_FLOW_EOS;
    }

    return ret;
}

GstFlowReturn on_new_sample_video(GstElement* sink, gpointer data)
{
    return on_new_sample(sink, data, DEFAULT_VIDEO_TRACK_ID);
}

GstFlowReturn on_new_sample_audio(GstElement* sink, gpointer data)
{
    return on_new_sample(sink, data, DEFAULT_AUDIO_TRACK_ID);
}
/**
 * @brief   
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
// https://gstreamer.freedesktop.org/documentation/sdp/gstsdpmessage.html?gi-language=c#GstSDPMessage
static void rtspsrcOnSdp(GstElement* rtspsrc, GstSDPMessage* sdp, gpointer user_data)
{
    DLOGD("****** on sdp works ******");
    guint i;
    gchar* sdpString = gst_sdp_message_as_text(sdp);
    DLOGD("sdpString:%s", sdpString);
    guint attrLen = gst_sdp_message_attributes_len(sdp);
    DLOGD("attrLen:%d", attrLen);
    guint mediasLen = gst_sdp_message_medias_len(sdp);
    DLOGD("mediasLen:%d", mediasLen);

    for (i = 0; i < mediasLen; i++) {
        const GstSDPMedia* sdpMedia = gst_sdp_message_get_media(sdp, i);
        guint media_conn_len = gst_sdp_media_connections_len(sdpMedia);
        DLOGD("media_conn_len:%d", media_conn_len);
        gchar* mediaText = gst_sdp_media_as_text(sdpMedia);
        DLOGD("mediaText:%s", mediaText);
        const gchar* mediaDescription = gst_sdp_media_get_media(sdpMedia);
        DLOGD("mediaDescription:%s", mediaDescription);
        GstCaps* caps;
        gst_sdp_media_set_media_from_caps(caps, sdpMedia);
        // gchar * capsString = gst_caps_serialize (caps, GST_SERIALIZE_FLAG_NONE);
        // gchar * capsString = gst_caps_serialize (caps, 0);
        // DLOGD("capsString:%s", capsString);

        guint mediaAttrLen = gst_sdp_media_attributes_len(sdpMedia);
        guint j;
        for (j = 0; j < mediaAttrLen; j++) {
            const GstSDPAttribute* tmpAttr = gst_sdp_media_get_attribute(sdpMedia, j);
        }
    }
}

//
// http://hk.uwenku.com/question/p-mekcwwlb-bno.html
/**
 * rtspsrc – a
num – the stream number
caps – the stream caps
udata – No description available
*/
static gboolean rtspsrcOnSelectStream(GstElement* rtspsrc, guint num, GstCaps* caps, gpointer user_data)
{
    gchar* caps_string = gst_caps_to_string(caps);
    DLOGD("num:%d ", num);
    DLOGD("caps_string:%s ", caps_string);
    guint caps_num = gst_caps_get_size(caps);
    guint index;
    DLOGD("caps_num:%d ", caps_num);
    // for(index = 0; index < caps_num; index){

    // GstCapsFeatures * feature = gst_caps_get_features (caps, index);
    // gchar * feature_string = gst_caps_features_to_string (feature);
    // DLOGD("feature_string:%s", feature_string);
    //}

    /*
    2021-06-19 08:07:16 DEBUG   rtspsrcOnSelectStream():
    caps_string:application/x-unknown,
    media=(string)video,
    payload=(int)96,
    clock-rate=(int)90000,
    encoding-name=(string)H264,
    packetization-mode=(string)1,
    profile-level-id=(string)42001F,
    sprop-parameter-sets=(string)"J0IAH6tAWgUMgA\=\=\,KM48MA\=\=",
    a-tool=(string)"LIVE555\ Streaming\ Media\ v2015.08.07",
    a-type=(string)broadcast, x-qt-text-nam=(string)"Periscope\ HD\ Camera", x-qt-text-inf=(string)live.sdp
    */
    /*
    2021-06-19 08:07:16 DEBUG   rtspsrcOnSelectStream():
    caps_string:application/x-unknown,
    media=(string)audio,
    payload=(int)97,
    clock-rate=(int)8000,
    encoding-name=(string)PCMU,
    a-tool=(string)"LIVE555\ Streaming\ Media\ v2015.08.07",
    a-type=(string)broadcast, x-qt-text-nam=(string)"Periscope\ HD\ Camera", x-qt-text-inf=(string)live.sdp

    */
    // when it is selected, you need to return true;
    return TRUE;
}

static void rtspsrcNewManager(GstElement* object, GstElement* arg0, gpointer user_data)
{
    DLOGD("%d", __LINE__);
}

/* callback when each RTSP stream has been created */
static void pad_added_cb(GstElement* element, GstPad* pad, GstElement* target)
{
    GstPad* target_sink = gst_element_get_static_pad(GST_ELEMENT(target), "sink");
    GstPadLinkReturn link_ret;
    gchar* pad_name = gst_pad_get_name(pad);
    DLOGD("New pad found: %s\n", pad_name);

    link_ret = gst_pad_link(pad, target_sink);

    if (link_ret == GST_PAD_LINK_OK) {
        DLOGI("Pad link successful");
    } else {
        DLOGI("Pad link failed");
    }

    gst_object_unref(target_sink);
    g_free(pad_name);
}

static void rtspsrcOnPadAdded(GstElement* element, GstPad* pad, gpointer user_data)
{
    gchar* pad_name = NULL;
    GstCaps* template_caps = NULL;
    GstCaps* current_caps = NULL;
    GstStructure* new_pad_struct = NULL;
    const gchar* new_pad_type = NULL;

    GstElement* nextElement;
    GstElement* pipeline = (GstElement*) user_data;
    BOOL video = FALSE;
    BOOL audio = FALSE;

    pad_name = gst_pad_get_name(pad);
    template_caps = gst_pad_get_pad_template_caps(pad);
    DLOGD("A new pad template %s was created\n", pad_name);

    current_caps = gst_pad_get_current_caps(pad);
    guint new_pad_caps_num = gst_caps_get_size(current_caps);
    DLOGD("new_pad_caps_num:%d", new_pad_caps_num);
    guint i;
    for (i = 0; i < new_pad_caps_num; i++) {
        new_pad_struct = gst_caps_get_structure(current_caps, i);
        new_pad_type = gst_structure_get_name(new_pad_struct);
        DLOGD("new_pad_type(%d):%s", i, new_pad_type);

        if (gst_structure_has_field(new_pad_struct, "media") == TRUE) {
            DLOGD("media");
            const gchar* media_value = gst_structure_get_string(new_pad_struct, "media");
            DLOGD("media_value:%s", media_value);
            if (STRCMP(media_value, "video") == 0) {
                video = TRUE;
            }
            if (STRCMP(media_value, "audio") == 0) {
                audio = TRUE;
            }
        }
        if (gst_structure_has_field(new_pad_struct, "encoding-name") == TRUE) {
            DLOGD("encoding-name");
            const gchar* encoding_name = gst_structure_get_string(new_pad_struct, "encoding-name");
            DLOGD("encoding_name:%s", encoding_name);
        }

        if (gst_structure_has_field(new_pad_struct, "payload") == TRUE) {
            DLOGD("payload");
            GType payload_type = gst_structure_get_field_type(new_pad_struct, "payload");
            DLOGD("payload_type:%d", payload_type);
            gint media_value;
            gst_structure_get_int(new_pad_struct, "payload", &media_value);
            DLOGD("payload:%d", media_value);
        }
    }
    gst_caps_unref(current_caps);

    if (video == TRUE) {
        DLOGD("------------------------ Video -------------------------------");
        nextElement = gst_bin_get_by_name(GST_BIN(pipeline), "videoDepay");
    } else if (audio == TRUE) {
        DLOGD("------------------------ Audio -------------------------------");
        nextElement = gst_bin_get_by_name(GST_BIN(pipeline), "audioDepay");
    }

    if (nextElement != NULL) {
        if (!gst_element_link_filtered(element, nextElement, template_caps))
        // if (!gst_element_link_pads_filtered(element, pad_name, nextElement, "sink", template_caps))
        {
            DLOGD("Failed to link video element to src to sink");
        }
        gst_object_unref(nextElement);
    }

    g_free(pad_name);
    gst_caps_unref(template_caps);
}
/**
 * @brief   
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
static void rtspsrcOnNoMorePads(GstElement* element, gpointer user_data)
{
    DLOGD("%d", __LINE__);
    GstElement* pipeline = user_data;
    GST_DEBUG_BIN_TO_DOT_FILE(GST_BIN(pipeline), GST_DEBUG_GRAPH_SHOW_ALL, "rtsp-kinesis-pipeline");
}
/**
 * @brief   
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
static void rtspsrcOnPadRemoved(GstElement* element, GstPad* pad, gpointer user_data)
{
    DLOGD("%d", __LINE__);
    UINT32 i;
    BOOL locked = FALSE;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) user_data;

    // #YC_TBD, need to consider how to turn  down one streaming session.

    // #YC_TBD, need to consider how to turn  down one streaming session.
    MUTEX_LOCK(pSampleConfiguration->sampleConfigurationObjLock);
    for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
        DLOGD("terminate the streaming session(%d)", i);
        ATOMIC_STORE_BOOL(&pSampleConfiguration->sampleStreamingSessionList[i]->terminateFlag, TRUE);
    }
    MUTEX_UNLOCK(pSampleConfiguration->sampleConfigurationObjLock);
    CVAR_BROADCAST(pSampleConfiguration->cvar);
}
/**
 * @brief   
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
/* This function is called when an error message is posted on the bus */
static void busMsgErrorCallback(GstBus* bus, GstMessage* msg, gpointer* data)
{
    GError* err;
    /**
    GQuark       domain;
    gint         code;
    gchar       *message;
     *
    */
    gchar* debug_info;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) data;
    PGstConfiguration pGstConfiguration = &pSampleConfiguration->gstConfiguration;
    UINT32 i;

    /* Print error details on the screen */

    gst_message_parse_error(msg, &err, &debug_info);
    DLOGE("err code: %d: %d", err->code, GST_RTSP_EINVAL);
    // #TC_BTD, need to  add the error handler.
    DLOGE("Error received from element %s: %s\n", GST_OBJECT_NAME(msg->src), err->message);
    DLOGE("Debugging information: %s\n", debug_info ? debug_info : "none");
    g_clear_error(&err);
    g_free(debug_info);

    g_main_loop_quit(pGstConfiguration->mainLoop);
    MUTEX_LOCK(pSampleConfiguration->sampleConfigurationObjLock);
    // #YC_TBD, need to consider how to turn  down one streaming session.
    for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
        DLOGD("terminate the streaming session(%d)", i);
        ATOMIC_STORE_BOOL(&pSampleConfiguration->sampleStreamingSessionList[i]->terminateFlag, TRUE);
    }
    MUTEX_UNLOCK(pSampleConfiguration->sampleConfigurationObjLock);
    CVAR_BROADCAST(pSampleConfiguration->cvar);
}
/**
 * @brief   
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
static void busMsgEosCallback(GstBus* bus, GstMessage* msg, gpointer* data)
{
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) data;
    PGstConfiguration pGstConfiguration = &pSampleConfiguration->gstConfiguration;
    UINT32 i;
    g_main_loop_quit(pGstConfiguration->mainLoop);
    // #YC_TBD, need to consider how to turn  down one streaming session.
    MUTEX_LOCK(pSampleConfiguration->sampleConfigurationObjLock);
    // #YC_TBD, need to consider how to turn  down one streaming session.
    for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
        DLOGD("terminate the streaming session(%d)", i);
        ATOMIC_STORE_BOOL(&pSampleConfiguration->sampleStreamingSessionList[i]->terminateFlag, TRUE);
    }
    MUTEX_UNLOCK(pSampleConfiguration->sampleConfigurationObjLock);
    CVAR_BROADCAST(pSampleConfiguration->cvar);
    return;
}
/**
 * @brief   
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
static void print_one_tag(const GstTagList* list, const gchar* tag, gpointer user_data)
{
    int i, num;

    num = gst_tag_list_get_tag_size(list, tag);
    for (i = 0; i < num; ++i) {
        DLOGD("loop:%d/%d", i, num);
        const GValue* val;

        /* Note: when looking for specific tags, use the gst_tag_list_get_xyz() API,
         * we only use the GValue approach here because it is more generic */
        val = gst_tag_list_get_value_index(list, tag, i);
        if (G_VALUE_HOLDS_STRING(val)) {
            g_print("\t%20s : %s\n", tag, g_value_get_string(val));
        } else if (G_VALUE_HOLDS_UINT(val)) {
            g_print("\t%20s : %u\n", tag, g_value_get_uint(val));
        } else if (G_VALUE_HOLDS_DOUBLE(val)) {
            g_print("\t%20s : %g\n", tag, g_value_get_double(val));
        } else if (G_VALUE_HOLDS_BOOLEAN(val)) {
            g_print("\t%20s : %s\n", tag, (g_value_get_boolean(val)) ? "true" : "false");
        } else if (GST_VALUE_HOLDS_BUFFER(val)) {
            GstBuffer* buf = gst_value_get_buffer(val);
            guint buffer_size = gst_buffer_get_size(buf);
            g_print("\t%20s : buffer of size %u\n", tag, buffer_size);
        } else if (GST_VALUE_HOLDS_DATE_TIME(val)) {
            GstDateTime* dt = g_value_get_boxed(val);
            gchar* dt_str = gst_date_time_to_iso8601_string(dt);
            g_print("\t%20s : %s\n", tag, dt_str);
            g_free(dt_str);
        } else {
            g_print("\t%20s : tag of type '%s'\n", tag, G_VALUE_TYPE_NAME(val));
        }
    }
}
/**
 * @brief   
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
static void busMsgTagsCallback(GstBus* bus, GstMessage* msg, gpointer* data)
{
    GstTagList* tags = NULL;
    g_print("Got tags from element %s:\n", GST_OBJECT_NAME(msg->src));
    gst_message_parse_tag(msg, &tags);
    gst_tag_list_foreach(tags, print_one_tag, NULL);
    g_print("\n");
    gst_tag_list_unref(tags);
    return;
}
/**
 * @brief   
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
static void busMsgCallback(GstBus* bus, GstMessage* msg, gpointer* data)
{
    DLOGD("bus msg callback(0x%x)", GST_MESSAGE_TYPE(msg));
    switch (GST_MESSAGE_TYPE(msg)) {
        case GST_MESSAGE_ERROR:
            busMsgErrorCallback(bus, msg, data);
            break;
        case GST_MESSAGE_EOS:
            busMsgEosCallback(bus, msg, data);
            break;
        case GST_MESSAGE_TAG:
            busMsgTagsCallback(bus, msg, data);
            break;
        default:
            break;
    }
    return;
}
/**
 * @brief   
 *          https://gstreamer.freedesktop.org/documentation/rtp/index.html?gi-language=c
 *          https://gstreamer.freedesktop.org/documentation/videoparsersbad/index.html?gi-language=c
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
STATUS gstreamerVideoPiplne(SampleStreamingVideoFormat format)
{
    STATUS retStatus = STATUS_SUCCESS;
    GstElement *videoDepay = NULL, *videoParse = NULL;

    if(format == SAMPLE_STREAMING_VIDEO_FORMAT_H264){
        videoDepay = gst_element_factory_make("rtph264depay", "videoDepay");
        videoParse = gst_element_factory_make("h264parse", "videoParse");
    }else if(format == SAMPLE_STREAMING_VIDEO_FORMAT_H265){
        videoDepay = gst_element_factory_make("rtph265depay", "videoDepay");
        videoParse = gst_element_factory_make("h265parse", "videoParse");
    }else if(format == SAMPLE_STREAMING_VIDEO_FORMAT_MPEG){
        videoDepay = gst_element_factory_make("rtpjpegdepay", "videoDepay");
        videoParse = gst_element_factory_make("jpeg2000parse", "videoParse");
    }else if(format == SAMPLE_STREAMING_VIDEO_FORMAT_VP8){
        videoDepay = gst_element_factory_make("rtpvp8depay", "videoDepay");
        videoParse = gst_element_factory_make("jpeg2000parse", "videoParse");
    }else if(format == SAMPLE_STREAMING_VIDEO_FORMAT_VP9){
        videoDepay = gst_element_factory_make("rtpvp9depay", "videoDepay");
        videoParse = gst_element_factory_make("vp9parse", "videoParse");
    }else{
        DLOGD("unsupported video type");
    }

    return STATUS_SUCCESS;
}


/**
 * @brief   
 *          https://gstreamer.freedesktop.org/documentation/rtp/index.html?gi-language=c
 *          https://gstreamer.freedesktop.org/documentation/videoparsersbad/index.html?gi-language=c
*/
STATUS gstreamerAudioPiplne(SampleStreamingAudioFormat format)
{
    STATUS retStatus = STATUS_SUCCESS;
    GstElement *audioDepay = NULL, *audioParse = NULL;

    if(format == SAMPLE_STREAMING_AUDIO_FORMAT_OPUS){
        audioDepay = gst_element_factory_make("rtpopusdepay", "audioDepay");
        audioParse = gst_element_factory_make("opusdec", "mulawdec");
    }else if(format == SAMPLE_STREAMING_AUDIO_FORMAT_PCMU){
        audioDepay = gst_element_factory_make("rtppcmudepay", "audioDepay");
        audioParse = gst_element_factory_make("mulawdec", "mulawdec");
    }else if(format == SAMPLE_STREAMING_AUDIO_FORMAT_PCMA){
        audioDepay = gst_element_factory_make("rtppcmadepay", "audioDepay");
        audioParse = gst_element_factory_make("alawdec", "mulawdec");
    }else if(format == SAMPLE_STREAMING_AUDIO_FORMAT_G722){
        audioDepay = gst_element_factory_make("rtpg722depay", "audioDepay");
        audioParse = gst_element_factory_make("avdec_g722", "mulawdec");
    }else{
        DLOGD("unsupported audio type");
    }

    return STATUS_SUCCESS;
}



// gst-launch-1.0 -v rtspsrc location="rtsp://admin:admin@192.168.193.224:8554/live.sdp" name=d d. ! queue ! rtph264depay ! h264parse ! avdec_h264 !
// videoconvert ! xvimagesink sync=false d. ! queue ! rtppcmudepay ! mulawdec ! audioconvert ! autoaudiosink
/**
 * @brief   
 * 
 * @param[in]
 * 
 * @return STATUS code of the execution. STATUS_SUCCESS on success
*/
STATUS gstreamerRtspsrcInit(PVOID args, GstElement* pipeline)
{
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    PRtspCameraConfiguration pRtspCameraConfiguration = NULL;
    STATUS retStatus = STATUS_SUCCESS;
    GstElement* rtspSource = NULL;
    GstElement *videoQueue = NULL, *videoDepay = NULL, *videoParse = NULL, *videoFilter = NULL, *videoAppSink = NULL;
    GstElement *audioQueue = NULL, *audioDepay = NULL, *audioParse = NULL, *audioConvert = NULL, *audioResample = NULL, *audioEnc = NULL,
               *audioFilter = NULL, *audioAppSink = NULL;

    // #gst
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstelementfactory.html#gst_element_factory_make
    // source
    rtspSource = gst_element_factory_make("rtspsrc", "rtspSource");
    // https://gstreamer.freedesktop.org/documentation/rtp/index.html?gi-language=c
    // video
    // " d. ! queue ! rtph264depay ! h264parse ! video/x-h264,stream-format=byte-stream,alignment=au,profile=baseline ! appsink sync=TRUE
    // emit-signals=TRUE name=appsink-video"
    videoDepay = gst_element_factory_make("rtph264depay", "videoDepay");
    videoParse = gst_element_factory_make("h264parse", "videoParse");
    videoFilter = gst_element_factory_make("capsfilter", "videoFilter");
    videoAppSink = gst_element_factory_make("appsink", "videoAppSink");

    // audio
    // " d. ! queue ! rtppcmudepay ! mulawdec ! audioconvert ! audioresample ! opusenc ! audio/x-opus,rate=48000,channels=2 ! appsink sync=TRUE
    // emit-signals=TRUE name=appsink-audio"
    audioDepay = gst_element_factory_make("rtppcmudepay", "audioDepay");
    // https://gstreamer.freedesktop.org/documentation/mulaw/mulawdec.html?gi-language=c
    audioParse = gst_element_factory_make("mulawdec", "mulawdec");
    audioConvert = gst_element_factory_make("audioconvert", "audioConvert");
    audioResample = gst_element_factory_make("audioresample", "audioResample");
    // audioEnc = gst_element_factory_make("opusenc", "audioEnc");
    audioEnc = gst_element_factory_make("mulawenc", "audioEnc");
    audioFilter = gst_element_factory_make("capsfilter", "audioFilter");
    audioAppSink = gst_element_factory_make("appsink", "audioAppSink");

    if (!pipeline || !rtspSource || !videoDepay || !videoParse || !videoFilter || !videoAppSink) {
        DLOGE("Not all elements could be created.\n");
        return 1;
    }

    if (!audioDepay || !audioParse || !audioConvert || !audioResample || !audioEnc || !audioFilter || !audioAppSink) {
        DLOGE("Not all audio elements could be created.\n");
        return 1;
    }

    // configure filter
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstcaps.html?gi-language=c#gst_caps_new_simple
    GstCaps* videoCaps = gst_caps_new_simple("video/x-h264", "stream-format", G_TYPE_STRING, "byte-stream", "alignment", G_TYPE_STRING, "au", NULL);
    // GstCaps* audioCaps = gst_caps_new_simple("audio/x-opus", "rate", G_TYPE_INT, 48000, "channels", G_TYPE_INT, 2, NULL);
    GstCaps* audioCaps = gst_caps_new_simple("audio/x-mulaw", "rate", G_TYPE_INT, 8000, "channels", G_TYPE_INT, 1, NULL);

    if (!videoCaps || !audioCaps) {
        DLOGE("Not all caps elements could be created.\n");
        return 1;
    }

    // https://developer.gnome.org/gobject/stable/gobject-The-Base-Object-Type.html#g-object-set
    g_object_set(G_OBJECT(videoFilter), "caps", videoCaps, NULL);
    gst_caps_unref(videoCaps);
    g_object_set(G_OBJECT(audioFilter), "caps", audioCaps, NULL);
    gst_caps_unref(audioCaps);

    // configure appsink
    g_object_set(G_OBJECT(videoAppSink), "emit-signals", TRUE, "sync", FALSE, NULL);
    g_signal_connect(videoAppSink, "new-sample", G_CALLBACK(on_new_sample_video), pSampleConfiguration);
    g_object_set(G_OBJECT(audioAppSink), "emit-signals", TRUE, "sync", FALSE, NULL);
    g_signal_connect(audioAppSink, "new-sample", G_CALLBACK(on_new_sample_audio), pSampleConfiguration);

    // configure rtspsrc
    pRtspCameraConfiguration = &pSampleConfiguration->rtspCameraConfiguration;
    DLOGD("RTSP URL:%s", pRtspCameraConfiguration->uri);
    g_object_set(G_OBJECT(rtspSource), "location", pRtspCameraConfiguration->uri, "short-header", TRUE, NULL);
    g_object_set(G_OBJECT(rtspSource), "latency", 0, NULL);
    g_object_set(G_OBJECT(rtspSource), "drop-on-latency", TRUE, NULL);
    g_object_set(G_OBJECT(rtspSource), "ntp-sync", TRUE, NULL);
    g_object_set(G_OBJECT(rtspSource), "debug", TRUE, NULL);
    // g_object_set(G_OBJECT(rtspSource), "protocols", 4,NULL);
    g_object_set(G_OBJECT(rtspSource), "user-id", pRtspCameraConfiguration->username, NULL);
    g_object_set(G_OBJECT(rtspSource), "user-pw", pRtspCameraConfiguration->password, NULL);

    // g_signal_connect(rtspSource, "pad-added", G_CALLBACK(pad_added_cb), tee);
    g_signal_connect(G_OBJECT(rtspSource), "on-sdp", G_CALLBACK(rtspsrcOnSdp), pipeline);
    g_signal_connect(G_OBJECT(rtspSource), "select-stream", G_CALLBACK(rtspsrcOnSelectStream), pipeline);
    g_signal_connect(G_OBJECT(rtspSource), "new-manager", G_CALLBACK(rtspsrcNewManager), pipeline);
    g_signal_connect(G_OBJECT(rtspSource), "pad-added", G_CALLBACK(rtspsrcOnPadAdded), pipeline);
    g_signal_connect(G_OBJECT(rtspSource), "no-more-pads", G_CALLBACK(rtspsrcOnNoMorePads), pipeline);
    g_signal_connect(G_OBJECT(rtspSource), "pad-removed", G_CALLBACK(rtspsrcOnPadRemoved), pSampleConfiguration);

    /* build the pipeline */
    // https://developer.gnome.org/gstreamer/stable/GstBin.html#gst-bin-add-many
    // gst_bin_add_many(GST_BIN(pipeline), rtspSource, videoDepay, videoParse, videoFilter, videoAppSink, NULL);

    /* Leave the actual source out - this will be done when the pad is added */
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstelement.html?gi-language=c#gst_element_link_many
    // if (!gst_element_link_many(videoDepay, videoFilter, videoParse, videoAppSink, NULL)) {
    //    DLOGE("Elements could not be linked.\n");
    //    gst_object_unref(pipeline);
    //    return 1;
    //}

    gst_bin_add_many(GST_BIN(pipeline), rtspSource, NULL);
    gst_bin_add_many(GST_BIN(pipeline), audioDepay, audioParse, audioConvert, audioResample, audioEnc, audioFilter, audioAppSink, NULL);

    // if (gst_element_link_many (rtspSource, tee, NULL) != TRUE) {
    //    DLOGE ("Source could not be linked.\n");
    //    gst_object_unref (pipeline);
    //    return -1;
    //}

    if (gst_element_link_many(audioDepay, audioParse, audioConvert, audioResample, audioEnc, audioFilter, audioAppSink, NULL) != TRUE) {
        DLOGE("Audio elements could not be linked.\n");
        gst_object_unref(pipeline);
        return -1;
    }

    gst_bin_add_many(GST_BIN(pipeline), videoDepay, videoFilter, videoAppSink, NULL);

    if (gst_element_link_many(videoDepay, videoFilter, videoAppSink, NULL) != TRUE) {
        DLOGE("Video elements could not be linked.\n");
        gst_object_unref(pipeline);
        return -1;
    }

CleanUp:

    return retStatus;
}

STATUS gstreamerInit(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    PGstConfiguration pGstConfiguration = &pSampleConfiguration->gstConfiguration;

    /* init GStreamer */
    GstElement* pipeline = NULL;
    GstBus* bus = NULL;
    GstStateChangeReturn gstRetStatus;


    DLOGI("Streaming from rtsp source");
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstpipeline.html?gi-language=c#gst_pipeline_new
    CHK((pipeline = gst_pipeline_new("rtsp-kinesis-pipeline")) != NULL, STATUS_NULL_ARG);

    retStatus = gstreamerRtspsrcInit(pSampleConfiguration, pipeline);

    if (retStatus != 0) {
        DLOGD("gstreamerRtspsrcInit failed. %d", retStatus);
        return retStatus;
    }

    /* Instruct the bus to emit signals for each received message, and connect to the interesting signals */
    CHK((bus = gst_element_get_bus(pipeline)) != NULL, STATUS_NULL_ARG);
    gst_bus_add_signal_watch(bus);
    // g_signal_connect(G_OBJECT(bus), "message::error", (GCallback) busMsgErrorCallback, pSampleConfiguration);
    // g_signal_connect(G_OBJECT(bus), "message::eos", G_CALLBACK (busMsgEosCallback), NULL);
    // g_signal_connect(G_OBJECT(bus), "message::tags", G_CALLBACK (busMsgTagsCallback), NULL);
    g_signal_connect(G_OBJECT(bus), "message", G_CALLBACK(busMsgCallback), pSampleConfiguration);
    gst_object_unref(bus);

    /* start streaming */
    gstRetStatus = gst_element_set_state(pipeline, GST_STATE_PLAYING);
    if (gstRetStatus == GST_STATE_CHANGE_FAILURE) {
        DLOGE("Unable to set the pipeline to the playing state.\n");
        gst_object_unref(pipeline);
        return 1;
    }

    pGstConfiguration->mainLoop = g_main_loop_new(NULL, FALSE);
    // start running the main loop, and it is blocking call.
    g_main_loop_run(pGstConfiguration->mainLoop);

CleanUp:

    /* free resources */
    DLOGD("Release the Gstreamer resources.");
    gst_bus_remove_signal_watch(bus);
    gst_element_set_state(pipeline, GST_STATE_NULL);
    gst_object_unref(pipeline);

    g_main_loop_unref(pGstConfiguration->mainLoop);
    pGstConfiguration->mainLoop = NULL;
    return retStatus;
}
/**
 * @brief the handler of video and audio.
 * 
 * 
*/
PVOID sendGstreamerAudioVideo(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    GstElement *appsinkVideo = NULL, *appsinkAudio = NULL, *pipeline = NULL;
    GstBus* bus;
    GstMessage* msg;
    GError* error = NULL;
    CHAR launchString[2048];
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    DLOGD("init");
    if (pSampleConfiguration == NULL) {
        printf("[KVS GStreamer Master] sendGstreamerAudioVideo(): operation returned status code: 0x%08x \n", STATUS_NULL_ARG);
        goto CleanUp;
    }
#if 0
    MEMSET(launchString, 0, 2048);
    SNPRINTF(launchString, 2048, "rtspsrc location=%s name=d" 
            " d. ! queue ! rtph264depay ! h264parse ! video/x-h264,stream-format=byte-stream,alignment=au,profile=baseline ! appsink sync=TRUE emit-signals=TRUE name=appsink-video"
            " d. ! queue ! rtppcmudepay ! mulawdec ! audioconvert ! audioresample ! opusenc ! audio/x-opus,rate=48000,channels=2 ! appsink sync=TRUE emit-signals=TRUE name=appsink-audio", pSampleConfiguration->pRtspUrl);
#if 0
    pipeline = gst_parse_launch("rtspsrc location=rtsp://admin:admin@192.168.193.224:8554/live.sdp name=d d. ! queue ! rtph264depay ! h264parse ! video/x-h264,stream-format=byte-stream,alignment=au,profile=baseline ! appsink sync=TRUE "
                                            "emit-signals=TRUE name=appsink-video d. ! queue ! rtppcmudepay ! mulawdec ! audioconvert ! audioresample ! mulawenc !"
                                            "audio/x-mulaw,channels=1,rate=8000 ! appsink sync=TRUE emit-signals=TRUE name=appsink-audio",
                                            &error);
#else
    pipeline = gst_parse_launch(launchString, &error);
#endif

    if (pipeline == NULL) {
        printf("[KVS GStreamer Master] sendGstreamerAudioVideo(): Failed to launch gstreamer, operation returned status code: 0x%08x \n",
               STATUS_INTERNAL_ERROR);
        goto CleanUp;
    }
    // #gst
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstbin.html?gi-language=c#gst_bin_get_by_name
    appsinkVideo = gst_bin_get_by_name(GST_BIN(pipeline), "appsink-video");
    appsinkAudio = gst_bin_get_by_name(GST_BIN(pipeline), "appsink-audio");

    if (!(appsinkVideo != NULL || appsinkAudio != NULL)) {
        printf("[KVS GStreamer Master] sendGstreamerAudioVideo(): cant find appsink, operation returned status code: 0x%08x \n",
               STATUS_INTERNAL_ERROR);
        goto CleanUp;
    }

    if (appsinkVideo != NULL) {
        g_signal_connect(appsinkVideo, "new-sample", G_CALLBACK(on_new_sample_video), (gpointer) pSampleConfiguration);
    }

    if (appsinkAudio != NULL) {
        g_signal_connect(appsinkAudio, "new-sample", G_CALLBACK(on_new_sample_audio), (gpointer) pSampleConfiguration);
    }
    // #gst
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstelement.html?gi-language=c#gst_element_set_state
    gst_element_set_state(pipeline, GST_STATE_PLAYING);

    /* block until error or EOS */
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstelement.html?gi-language=c#gst_element_get_bus
    bus = gst_element_get_bus(pipeline);
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstbus.html?gi-language=c#gst_bus_timed_pop_filtered
    msg = gst_bus_timed_pop_filtered(bus, GST_CLOCK_TIME_NONE, GST_MESSAGE_ERROR | GST_MESSAGE_EOS);

    DLOGD("*****out*****");
    /* Free resources */
    if (msg != NULL) {
        gst_message_unref(msg);
    }
    gst_object_unref(bus);
    gst_element_set_state(pipeline, GST_STATE_NULL);
    gst_object_unref(pipeline);

//CleanUp:

    if (error != NULL) {
        printf("%s", error->message);
        g_clear_error(&error);
    }

    return (PVOID)(ULONG_PTR) retStatus;
#endif

    gstreamerInit(args);
    return (PVOID)(ULONG_PTR) retStatus;
    /**
     * Use x264enc as its available on mac, pi, ubuntu and windows
     * mac pipeline fails if resolution is not 720p
     *
     * For alaw
     * audiotestsrc is-live=TRUE ! queue leaky=2 max-size-buffers=400 ! audioconvert ! audioresample !
     * audio/x-raw, rate=8000, channels=1, format=S16LE, layout=interleaved ! alawenc ! appsink sync=TRUE emit-signals=TRUE name=appsink-audio
     *
     * For VP8
     * videotestsrc is-live=TRUE ! video/x-raw,width=1280,height=720,framerate=30/1 !
     * vp8enc error-resilient=partitions keyframe-max-dist=10 auto-alt-ref=true cpu-used=5 deadline=1 !
     * appsink sync=TRUE emit-signals=TRUE name=appsink-video
     */
    // #gst
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstparse.html?gi-language=c#gst_parse_launch
    switch (pSampleConfiguration->mediaType) {
        case SAMPLE_STREAMING_VIDEO_ONLY:
            if (pSampleConfiguration->useTestSrc) {
                pipeline = gst_parse_launch(
                    "videotestsrc is-live=TRUE ! queue ! videoconvert ! video/x-raw,width=1280,height=720,framerate=30/1 ! "
                    "x264enc bframes=0 speed-preset=veryfast bitrate=512 byte-stream=TRUE tune=zerolatency ! "
                    "video/x-h264,stream-format=byte-stream,alignment=au,profile=baseline ! appsink sync=TRUE emit-signals=TRUE name=appsink-video",
                    &error);
            } else {
                pipeline = gst_parse_launch(
                    "autovideosrc ! queue ! videoconvert ! video/x-raw,width=1280,height=720,framerate=[30/1,10000000/333333] ! "
                    "x264enc bframes=0 speed-preset=veryfast bitrate=512 byte-stream=TRUE tune=zerolatency ! "
                    "video/x-h264,stream-format=byte-stream,alignment=au,profile=baseline ! appsink sync=TRUE emit-signals=TRUE name=appsink-video",
                    &error);
            }
            break;

        case SAMPLE_STREAMING_AUDIO_VIDEO:
            if (pSampleConfiguration->useTestSrc) {
                pipeline = gst_parse_launch("videotestsrc is-live=TRUE ! queue ! videoconvert ! video/x-raw,width=1280,height=720,framerate=30/1 ! "
                                            "x264enc bframes=0 speed-preset=veryfast bitrate=512 byte-stream=TRUE tune=zerolatency ! "
                                            "video/x-h264,stream-format=byte-stream,alignment=au,profile=baseline ! appsink sync=TRUE "
                                            "emit-signals=TRUE name=appsink-video audiotestsrc is-live=TRUE ! "
                                            "queue leaky=2 max-size-buffers=400 ! audioconvert ! audioresample ! opusenc ! "
                                            "audio/x-opus,rate=48000,channels=2 ! appsink sync=TRUE emit-signals=TRUE name=appsink-audio",
                                            &error);
            } else {
                pipeline =
                    gst_parse_launch("autovideosrc ! queue ! videoconvert ! video/x-raw,width=1280,height=720,framerate=[30/1,10000000/333333] ! "
                                     "x264enc bframes=0 speed-preset=veryfast bitrate=512 byte-stream=TRUE tune=zerolatency ! "
                                     "video/x-h264,stream-format=byte-stream,alignment=au,profile=baseline ! appsink sync=TRUE emit-signals=TRUE "
                                     "name=appsink-video autoaudiosrc ! "
                                     "queue leaky=2 max-size-buffers=400 ! audioconvert ! audioresample ! opusenc ! "
                                     "audio/x-opus,rate=48000,channels=2 ! appsink sync=TRUE emit-signals=TRUE name=appsink-audio",
                                     &error);
            }
            break;
    }

    if (pipeline == NULL) {
        printf("[KVS GStreamer Master] sendGstreamerAudioVideo(): Failed to launch gstreamer, operation returned status code: 0x%08x \n",
               STATUS_INTERNAL_ERROR);
        goto CleanUp;
    }
    // #gst
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstbin.html?gi-language=c#gst_bin_get_by_name
    appsinkVideo = gst_bin_get_by_name(GST_BIN(pipeline), "appsink-video");
    appsinkAudio = gst_bin_get_by_name(GST_BIN(pipeline), "appsink-audio");

    if (!(appsinkVideo != NULL || appsinkAudio != NULL)) {
        printf("[KVS GStreamer Master] sendGstreamerAudioVideo(): cant find appsink, operation returned status code: 0x%08x \n",
               STATUS_INTERNAL_ERROR);
        goto CleanUp;
    }

    if (appsinkVideo != NULL) {
        g_signal_connect(appsinkVideo, "new-sample", G_CALLBACK(on_new_sample_video), (gpointer) pSampleConfiguration);
    }

    if (appsinkAudio != NULL) {
        g_signal_connect(appsinkAudio, "new-sample", G_CALLBACK(on_new_sample_audio), (gpointer) pSampleConfiguration);
    }
    // #gst
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstelement.html?gi-language=c#gst_element_set_state
    gst_element_set_state(pipeline, GST_STATE_PLAYING);

    /* block until error or EOS */
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstelement.html?gi-language=c#gst_element_get_bus
    bus = gst_element_get_bus(pipeline);
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstbus.html?gi-language=c#gst_bus_timed_pop_filtered
    msg = gst_bus_timed_pop_filtered(bus, GST_CLOCK_TIME_NONE, GST_MESSAGE_ERROR | GST_MESSAGE_EOS);

    /* Free resources */
    if (msg != NULL) {
        gst_message_unref(msg);
    }
    gst_object_unref(bus);
    gst_element_set_state(pipeline, GST_STATE_NULL);
    gst_object_unref(pipeline);

CleanUp:

    if (error != NULL) {
        printf("%s", error->message);
        g_clear_error(&error);
    }

    return (PVOID)(ULONG_PTR) retStatus;
}

VOID onGstAudioFrameReady(UINT64 customData, PFrame pFrame)
{
    GstFlowReturn ret;
    GstBuffer* buffer;
    GstElement* appsrcAudio = (GstElement*) customData;

    /* Create a new empty buffer */
    buffer = gst_buffer_new_and_alloc(pFrame->size);
    gst_buffer_fill(buffer, 0, pFrame->frameData, pFrame->size);

    /* Push the buffer into the appsrc */
    g_signal_emit_by_name(appsrcAudio, "push-buffer", buffer, &ret);

    /* Free the buffer now that we are done with it */
    gst_buffer_unref(buffer);
}

VOID onSampleStreamingSessionShutdown(UINT64 customData, PSampleStreamingSession pSampleStreamingSession)
{
    (void) (pSampleStreamingSession);
    GstElement* appsrc = (GstElement*) customData;
    GstFlowReturn ret;

    g_signal_emit_by_name(appsrc, "end-of-stream", &ret);
}

PVOID receiveGstreamerAudioVideo(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    GstElement *pipeline = NULL, *appsrcAudio = NULL;
    GstBus* bus;
    GstMessage* msg;
    GError* error = NULL;
    PSampleStreamingSession pSampleStreamingSession = (PSampleStreamingSession) args;
    gchar *videoDescription = "", *audioDescription = "", *audioVideoDescription;

    if (pSampleStreamingSession == NULL) {
        printf("[KVS GStreamer Master] receiveGstreamerAudioVideo(): operation returned status code: 0x%08x \n", STATUS_NULL_ARG);
        goto CleanUp;
    }

    // TODO: Wire video up with gstreamer pipeline

    switch (pSampleStreamingSession->pAudioRtcRtpTransceiver->receiver.track.codec) {
        case RTC_CODEC_OPUS:
            audioDescription = "appsrc name=appsrc-audio ! opusparse ! decodebin ! autoaudiosink";
            break;

        case RTC_CODEC_MULAW:
        case RTC_CODEC_ALAW:
            audioDescription = "appsrc name=appsrc-audio ! rawaudioparse ! decodebin ! autoaudiosink";
            break;
        default:
            break;
    }

    audioVideoDescription = g_strjoin(" ", audioDescription, videoDescription, NULL);

    pipeline = gst_parse_launch(audioVideoDescription, &error);

    appsrcAudio = gst_bin_get_by_name(GST_BIN(pipeline), "appsrc-audio");
    if (appsrcAudio == NULL) {
        printf("[KVS GStreamer Master] gst_bin_get_by_name(): cant find appsrc, operation returned status code: 0x%08x \n", STATUS_INTERNAL_ERROR);
        goto CleanUp;
    }

    transceiverOnFrame(pSampleStreamingSession->pAudioRtcRtpTransceiver, (UINT64) appsrcAudio, onGstAudioFrameReady);

    retStatus = streamingSessionOnShutdown(pSampleStreamingSession, (UINT64) appsrcAudio, onSampleStreamingSessionShutdown);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS GStreamer Master] streamingSessionOnShutdown(): operation returned status code: 0x%08x \n", STATUS_INTERNAL_ERROR);
        goto CleanUp;
    }

    g_free(audioVideoDescription);

    if (pipeline == NULL) {
        printf("[KVS GStreamer Master] receiveGstreamerAudioVideo(): Failed to launch gstreamer, operation returned status code: 0x%08x \n",
               STATUS_INTERNAL_ERROR);
        goto CleanUp;
    }

    gst_element_set_state(pipeline, GST_STATE_PLAYING);

    /* block until error or EOS */
    bus = gst_element_get_bus(pipeline);
    msg = gst_bus_timed_pop_filtered(bus, GST_CLOCK_TIME_NONE, GST_MESSAGE_ERROR | GST_MESSAGE_EOS);

    /* Free resources */
    if (msg != NULL) {
        gst_message_unref(msg);
    }
    gst_object_unref(bus);
    gst_element_set_state(pipeline, GST_STATE_NULL);
    gst_object_unref(pipeline);

CleanUp:
    if (error != NULL) {
        printf("%s", error->message);
        g_clear_error(&error);
    }

    return (PVOID)(ULONG_PTR) retStatus;
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

    /* Initialize GStreamer */
    // #gst
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gst.html?gi-language=c#gst_init
    gst_init(&argc, &argv);
    printf("[KVS Gstreamer Master] Finished initializing GStreamer\n");

    switch (pSampleConfiguration->mediaType) {
        case SAMPLE_STREAMING_VIDEO_ONLY:
            printf("[KVS GStreamer Master] streaming type video-only");
            break;
        case SAMPLE_STREAMING_AUDIO_VIDEO:
            printf("[KVS GStreamer Master] streaming type audio-video");
            break;
    }

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
