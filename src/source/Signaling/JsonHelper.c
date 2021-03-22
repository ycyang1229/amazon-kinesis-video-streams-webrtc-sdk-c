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

#define LOG_CLASS "http_helper"
#include "../Include_i.h"

PCHAR json_object_dotget_serialize_to_string( const JSON_Object *pRootObject, const PCHAR pName, BOOL bRemoveQuotes )
{
    PCHAR pRes = NULL;
    PCHAR pValue = NULL;
    SIZE_T uValueLen = 0;
    JSON_Value * pJsonValue = NULL;

    if( pRootObject != NULL )
    {
        pJsonValue = json_object_dotget_value( pRootObject, pName );
        if( pJsonValue != NULL )
        {
            pValue = json_serialize_to_string( pJsonValue );
            if( pValue != NULL )
            {
                /* We have a valid string value here. */
                if( bRemoveQuotes )
                {
                    /* Remove quotes by allocating another buffer */
                    /* TODO: It should have better way to do this. */
                    uValueLen = STRLEN( pValue );
                    pRes = ( PCHAR )MEMALLOC( uValueLen - 1 );
                    if( pRes != NULL )
                    {
                        STRNCPY( pRes, pValue + 1, uValueLen - 2 );
                        pRes[ uValueLen - 2 ] = '\0';
                    }
                    MEMFREE( pValue );
                }
                else
                {
                    pRes = pValue;
                }
            }
        }
    }

    return pRes;
}

UINT64 json_object_dotget_uint64( const JSON_Object *pRootObject, const PCHAR pName, INT32 base )
{
    UINT64 uVal = 0;
    PCHAR pValue = NULL;
    JSON_Value * pJsonValue = NULL;

    if( pRootObject != NULL )
    {
        pJsonValue = json_object_dotget_value( pRootObject, pName );
        if( pJsonValue != NULL )
        {
            pValue = json_serialize_to_string( pJsonValue );
            if( pValue != NULL )
            {
                // #YC_TBD.
                /* We have a valid string value here. */
                uVal = strtoull( pValue, NULL, base );
                MEMFREE( pValue );
            }
        }
    }

    return uVal;
}