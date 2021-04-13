/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef __KINESIS_VIDEO_WEBRTC_JSON_HELPER_H__
#define __KINESIS_VIDEO_WEBRTC_JSON_HELPER_H__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

PCHAR json_object_dotget_serialize_to_string(const JSON_Object* pRootObject, const PCHAR pName, BOOL bRemoveQuotes);

UINT64 json_object_dotget_uint64(const JSON_Object* pRootObject, const PCHAR pName, INT32 base);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_JSON_HELPER_H__ */