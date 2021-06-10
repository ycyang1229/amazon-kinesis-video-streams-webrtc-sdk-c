#include "Samples.h"

// gstreamere related.
#include <gst/gst.h>
#include <gst/app/gstappsink.h>
#include <gst/sdp/gstsdpmessage.h>
#include <gst/gststructure.h>
#include <gst/gstcaps.h>

extern PSampleConfiguration gSampleConfiguration;

// #define VERBOSE

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

        frame.trackId = trackid;
        frame.duration = 0;
        frame.version = FRAME_CURRENT_VERSION;
        frame.size = (UINT32) info.size;
        frame.frameData = (PBYTE) info.data;

        MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);
        for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
            pSampleStreamingSession = pSampleConfiguration->sampleStreamingSessionList[i];
            frame.index = (UINT32) ATOMIC_INCREMENT(&pSampleStreamingSession->frameIndex);

            if (trackid == DEFAULT_AUDIO_TRACK_ID) {
                pRtcRtpTransceiver = pSampleStreamingSession->pAudioRtcRtpTransceiver;
                frame.presentationTs = pSampleStreamingSession->audioTimestamp;
                frame.decodingTs = frame.presentationTs;
                pSampleStreamingSession->audioTimestamp +=
                    SAMPLE_AUDIO_FRAME_DURATION; // assume audio frame size is 20ms, which is default in opusenc
            } else {
                pRtcRtpTransceiver = pSampleStreamingSession->pVideoRtcRtpTransceiver;
                frame.presentationTs = pSampleStreamingSession->videoTimestamp;
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

    if ( ATOMIC_LOAD_BOOL(&pSampleConfiguration->appTerminateFlag) || pSampleConfiguration->streamingSessionCount == 0) {
        DLOGD("There is no streaming sessions, and we start terminating the rtspsrc.");
        if (pSampleConfiguration->main_loop != NULL) {
            g_main_loop_quit(pSampleConfiguration->main_loop);
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

// https://gstreamer.freedesktop.org/documentation/sdp/gstsdpmessage.html?gi-language=c#GstSDPMessage
static void onSdp(GstElement* rtspsrc, GstSDPMessage* sdp, gpointer udata)
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

static void onPadAdded(GstElement* element, GstPad* pad, gpointer user_data)
{
    gchar* name;
    GstCaps* p_caps;
    GstElement* nextElement;
    GstElement* pipeline = (GstElement*) user_data;
    name = gst_pad_get_name(pad);

    p_caps = gst_pad_get_pad_template_caps(pad);

    gchar* description = gst_caps_to_string(p_caps);
    DLOGD("A new pad %s was created (%s)\n", name, description);

    g_free(description);

    if (strstr(name, "src_0") != NULL) {
        DLOGD("------------------------ Video -------------------------------");
        nextElement = gst_bin_get_by_name(GST_BIN(pipeline), "videoQueue");
    } else if (strstr(name, "src_1") != NULL) {
        DLOGD("------------------------ Audio -------------------------------");
        nextElement = gst_bin_get_by_name(GST_BIN(pipeline), "audioQueue");
    }

    if (nextElement != NULL) {
        if (!gst_element_link_filtered(element, nextElement, p_caps))
        // if (!gst_element_link_pads_filtered(element, name, nextElement, "sink", p_caps))
        {
            DLOGD("Failed to link video element to src to sink");
        }
        gst_object_unref(nextElement);
    }

    g_free(name);
    gst_caps_unref(p_caps);
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

/* This function is called when an error message is posted on the bus */
static void error_cb(GstBus* bus, GstMessage* msg, gpointer* data)
{
    GError* err;
    gchar* debug_info;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) data;

    /* Print error details on the screen */
    gst_message_parse_error(msg, &err, &debug_info);
    DLOGE("Error received from element %s: %s\n", GST_OBJECT_NAME(msg->src), err->message);
    DLOGE("Debugging information: %s\n", debug_info ? debug_info : "none");
    g_clear_error(&err);
    g_free(debug_info);

    g_main_loop_quit(pSampleConfiguration->main_loop);
}

// gst-launch-1.0 -v rtspsrc location="rtsp://admin:admin@192.168.193.224:8554/live.sdp" name=d d. ! queue ! rtph264depay ! h264parse ! avdec_h264 !
// videoconvert ! xvimagesink sync=false d. ! queue ! rtppcmudepay ! mulawdec ! audioconvert ! autoaudiosink
STATUS gstreamer_rtsp_source_init(PVOID args, GstElement* pipeline)
{
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    STATUS retStatus = STATUS_SUCCESS;
    GstElement* rtspSource = NULL;
    GstElement *videoQueue = NULL, *videoDepay = NULL, *videoParse = NULL, *videoFilter = NULL, *videoAppSink = NULL;
    GstElement *audioQueue = NULL, *audioDepay = NULL, *audioParse = NULL, *audioConvert = NULL, *audioResample = NULL, *audioEnc = NULL,
               *audioFilter = NULL, *audioAppSink = NULL;

    // #gst
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstelementfactory.html#gst_element_factory_make
    // source
    rtspSource = gst_element_factory_make("rtspsrc", "rtspSource");

    // video
    // " d. ! queue ! rtph264depay ! h264parse ! video/x-h264,stream-format=byte-stream,alignment=au,profile=baseline ! appsink sync=TRUE
    // emit-signals=TRUE name=appsink-video"
    videoQueue = gst_element_factory_make("queue", "videoQueue");
    videoDepay = gst_element_factory_make("rtph264depay", "videoDepay");
    videoParse = gst_element_factory_make("h264parse", "videoParse");
    videoFilter = gst_element_factory_make("capsfilter", "videoFilter");
    videoAppSink = gst_element_factory_make("appsink", "videoAppSink");

    // audio
    // " d. ! queue ! rtppcmudepay ! mulawdec ! audioconvert ! audioresample ! opusenc ! audio/x-opus,rate=48000,channels=2 ! appsink sync=TRUE
    // emit-signals=TRUE name=appsink-audio"
    audioQueue = gst_element_factory_make("queue", "audioQueue");
    audioDepay = gst_element_factory_make("rtppcmudepay", "audioDepay");
    // https://gstreamer.freedesktop.org/documentation/mulaw/mulawdec.html?gi-language=c
    audioParse = gst_element_factory_make("mulawdec", "mulawdec");
    audioConvert = gst_element_factory_make("audioconvert", "audioConvert");
    audioResample = gst_element_factory_make("audioresample", "audioResample");
    audioEnc = gst_element_factory_make("opusenc", "audioEnc");
    audioFilter = gst_element_factory_make("capsfilter", "audioFilter");
    audioAppSink = gst_element_factory_make("appsink", "audioAppSink");

    if (!pipeline || !rtspSource || !videoQueue || !videoDepay || !videoParse || !videoFilter || !videoAppSink) {
        DLOGE("Not all elements could be created.\n");
        return 1;
    }

    if (!audioQueue || !audioDepay || !audioParse || !audioConvert || !audioResample || !audioEnc || !audioFilter || !audioAppSink) {
        DLOGE("Not all audio elements could be created.\n");
        return 1;
    }

    // configure filter
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstcaps.html?gi-language=c#gst_caps_new_simple
    GstCaps* videoCaps = gst_caps_new_simple("video/x-h264", "stream-format", G_TYPE_STRING, "byte-stream", "alignment", G_TYPE_STRING, "au", NULL);
    GstCaps* audioCaps = gst_caps_new_simple("audio/x-opus", "rate", G_TYPE_INT, 48000, "channels", G_TYPE_INT, 2, NULL);

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
    DLOGD("RTSP URL:%s", pSampleConfiguration->pRtspUrl);
    g_object_set(G_OBJECT(rtspSource), "location", pSampleConfiguration->pRtspUrl, "short-header", TRUE, NULL);
    g_object_set(G_OBJECT(rtspSource), "latency", 0, NULL);
    g_object_set(G_OBJECT(rtspSource), "debug", TRUE, NULL);
    // g_object_set(G_OBJECT(rtspsrc), "location","192.168.50.246", "protocols", 4,NULL);
    // g_object_set(G_OBJECT(rtspsrc), "user-id","admin", "user-pw","admin",NULL);

    // g_signal_connect(rtspSource, "pad-added", G_CALLBACK(pad_added_cb), tee);
    g_signal_connect(G_OBJECT(rtspSource), "pad-added", G_CALLBACK(onPadAdded), pipeline);
    // g_signal_connect(G_OBJECT(rtspSource), "on-sdp", G_CALLBACK(onSdp), pipeline);

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

    /* Link all elements that can be automatically linked because they have "Always" pads */
    gst_bin_add_many(GST_BIN(pipeline), rtspSource, audioQueue, audioDepay, audioParse, audioConvert, audioResample, audioEnc, audioFilter,
                     audioAppSink, NULL);

    // if (gst_element_link_many (rtspSource, tee, NULL) != TRUE) {
    //    DLOGE ("Source could not be linked.\n");
    //    gst_object_unref (pipeline);
    //    return -1;
    //}

    if (gst_element_link_many(audioQueue, audioDepay, audioParse, audioConvert, audioResample, audioEnc, audioFilter, audioAppSink, NULL) != TRUE) {
        DLOGE("Audio elements could not be linked.\n");
        gst_object_unref(pipeline);
        return -1;
    }

    gst_bin_add_many(GST_BIN(pipeline), videoQueue, videoDepay, videoParse, videoFilter, videoAppSink, NULL);

    if (gst_element_link_many(videoQueue, videoDepay, videoParse, videoFilter, videoAppSink, NULL) != TRUE) {
        DLOGE("Video elements could not be linked.\n");
        gst_object_unref(pipeline);
        return -1;
    }

CleanUp:

    return retStatus;
}

STATUS gstreamer_init(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    /* init GStreamer */
    GstElement* pipeline = NULL;
    GstBus* bus = NULL;
    GstStateChangeReturn gst_ret;
    // Reset first frame pts
    // data->first_pts = GST_CLOCK_TIME_NONE;

    DLOGI("Streaming from rtsp source");
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gstpipeline.html?gi-language=c#gst_pipeline_new
    CHK((pipeline = gst_pipeline_new("rtsp-kinesis-pipeline")) != NULL, STATUS_NULL_ARG);

    retStatus = gstreamer_rtsp_source_init(pSampleConfiguration, pipeline);

    if (retStatus != 0) {
        DLOGD("gstreamer_rtsp_source_init failed. %d", retStatus);
        return retStatus;
    }

    /* Instruct the bus to emit signals for each received message, and connect to the interesting signals */
    CHK((bus = gst_element_get_bus(pipeline)) != NULL, STATUS_NULL_ARG);
    gst_bus_add_signal_watch(bus);
    g_signal_connect(G_OBJECT(bus), "message::error", (GCallback) error_cb, pSampleConfiguration);
    gst_object_unref(bus);

    /* start streaming */
    gst_ret = gst_element_set_state(pipeline, GST_STATE_PLAYING);
    if (gst_ret == GST_STATE_CHANGE_FAILURE) {
        DLOGE("Unable to set the pipeline to the playing state.\n");
        gst_object_unref(pipeline);
        return 1;
    }

    pSampleConfiguration->main_loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(pSampleConfiguration->main_loop);

CleanUp:

    /* free resources */
    DLOGD("Release the Gstreamer resources.");
    gst_bus_remove_signal_watch(bus);
    gst_element_set_state(pipeline, GST_STATE_NULL);
    gst_object_unref(pipeline);

    g_main_loop_unref(pSampleConfiguration->main_loop);
    pSampleConfiguration->main_loop = NULL;
    return retStatus;
}

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

    gstreamer_init(args);
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
    PCHAR pChannelName;

    SET_INSTRUMENTED_ALLOCATORS();

    signal(SIGINT, sigintHandler);

    // do trickle-ice by default
    printf("[KVS GStreamer Master] Using trickleICE by default\n");
    pChannelName = argc > 1 ? argv[1] : SAMPLE_CHANNEL_NAME;

    retStatus = createSampleConfiguration(pChannelName, SIGNALING_CHANNEL_ROLE_TYPE_MASTER, TRUE, TRUE, &pSampleConfiguration);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS GStreamer Master] createSampleConfiguration(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }

    printf("[KVS GStreamer Master] Created signaling channel %s\n", pChannelName);

    if (pSampleConfiguration->enableFileLogging) {
        retStatus =
            createFileLogger(FILE_LOGGING_BUFFER_SIZE, MAX_NUMBER_OF_LOG_FILES, (PCHAR) FILE_LOGGER_LOG_FILE_DIRECTORY_PATH, TRUE, TRUE, NULL);
        if (retStatus != STATUS_SUCCESS) {
            printf("[KVS Master] createFileLogger(): operation returned status code: 0x%08x \n", retStatus);
            pSampleConfiguration->enableFileLogging = FALSE;
        }
    }

    pSampleConfiguration->videoSource = sendGstreamerAudioVideo;
    pSampleConfiguration->mediaType = SAMPLE_STREAMING_VIDEO_ONLY;
    pSampleConfiguration->receiveAudioVideoSource = receiveGstreamerAudioVideo;
    pSampleConfiguration->onDataChannel = onDataChannel;
    pSampleConfiguration->customData = (UINT64) pSampleConfiguration;
    pSampleConfiguration->useTestSrc = FALSE;
    if (argc > 2) {
        UINT32 len = STRLEN(argv[2]);
        pSampleConfiguration->pRtspUrl = MEMALLOC(len + 1);
        MEMCPY(pSampleConfiguration->pRtspUrl, argv[2], len);
        pSampleConfiguration->pRtspUrl[len] = '\0';
    } else {
        goto CleanUp;
    }
    /* Initialize GStreamer */
    // #gst
    // https://gstreamer.freedesktop.org/documentation/gstreamer/gst.html?gi-language=c#gst_init
    gst_init(&argc, &argv);
    printf("[KVS Gstreamer Master] Finished initializing GStreamer\n");
    pSampleConfiguration->mediaType = SAMPLE_STREAMING_AUDIO_VIDEO;
#if 0
    if (argc > 2) {
        if (STRCMP(argv[2], "video-only") == 0) {
            
            printf("[KVS Gstreamer Master] Streaming video only\n");
        } else if (STRCMP(argv[2], "audio-video") == 0) {
            pSampleConfiguration->mediaType = SAMPLE_STREAMING_AUDIO_VIDEO;
            printf("[KVS Gstreamer Master] Streaming audio and video\n");
        } else {
            printf("[KVS Gstreamer Master] Unrecognized streaming type. Default to video-only\n");
        }
    } else {
        printf("[KVS Gstreamer Master] Streaming video only\n");
    }
#endif

    if (argc > 3) {
        if (STRCMP(argv[3], "testsrc") == 0) {
            printf("[KVS GStreamer Master] Using test source in GStreamer\n");
            pSampleConfiguration->useTestSrc = TRUE;
        }
    }

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

    printf("[KVS Gstreamer Master] Beginning streaming...check the stream over channel %s\n", pChannelName);

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
