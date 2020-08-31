#define LOG_CLASS "IOBuffer"
#include "../Include_i.h"

/**
 * #memory.
 * the packet buffer for tls and dtls. #dtls.
 * @param initialCap the capacity of the raw buffer.
 * @return the information of this buffer.
*/
STATUS createIOBuffer(UINT32 initialCap, PIOBuffer* ppBuffer)
{
    STATUS retStatus = STATUS_SUCCESS;
    PIOBuffer pBuffer = NULL;
    /**
     * #memory.
    */
    pBuffer = (PIOBuffer) MEMCALLOC(SIZEOF(IOBuffer), 1);
    CHK(pBuffer != NULL, STATUS_NOT_ENOUGH_MEMORY);

    if (initialCap != 0) {
        pBuffer->raw = (PBYTE) MEMALLOC(initialCap);
        CHK(pBuffer->raw != NULL, STATUS_NOT_ENOUGH_MEMORY);
        pBuffer->cap = initialCap;
    }

    *ppBuffer = pBuffer;

CleanUp:

    if (STATUS_FAILED(retStatus) && pBuffer != NULL) {
        freeIOBuffer(&pBuffer);
    }

    return retStatus;
}

STATUS freeIOBuffer(PIOBuffer* ppBuffer)
{
    STATUS retStatus = STATUS_SUCCESS;
    PIOBuffer pBuffer;

    CHK(ppBuffer != NULL, STATUS_NULL_ARG);

    pBuffer = *ppBuffer;
    CHK(pBuffer != NULL, retStatus);

    MEMFREE(pBuffer->raw);
    SAFE_MEMFREE(*ppBuffer);

CleanUp:

    return retStatus;
}
/**
 * @brief reset the status of io buffer.
 * 
*/
STATUS ioBufferReset(PIOBuffer pBuffer)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pBuffer != NULL, STATUS_NULL_ARG);

    pBuffer->len = 0;
    pBuffer->off = 0;

CleanUp:

    return retStatus;
}
/**
 * @brief copy data into iobuffer.
 * @param pBuffer the information of destination buffer.
 * @param pData the source buffer.
 * @param dataLen the length of the source buffer.
*/
STATUS ioBufferWrite(PIOBuffer pBuffer, PBYTE pData, UINT32 dataLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 freeSpace;
    UINT32 newCap;

    CHK(pBuffer != NULL && pData != NULL, STATUS_NULL_ARG);

    freeSpace = pBuffer->cap - pBuffr->len;
    if (freeSpace < dataLen) {
        newCap = pBuffer->len + dataLen;
        /** #memory. #YC_TBD. this needs to be reviewed, and probably can not be used in embedded devices. */
        pBuffer->raw = MEMREALLOC(pBuffer->raw, newCap);
        CHK(pBuffer->raw != NULL, STATUS_NOT_ENOUGH_MEMORY);
        pBuffer->cap = newCap;
    }

    MEMCPY(pBuffer->raw + pBuffer->len, pData, dataLen);
    pBuffer->len += dataLen;

CleanUp:

    return retStatus;
}
/**
 * @brief copy data from  iobuffer.
 * @param pBuffer the information of source buffer.
 * @param pData the destination buffer.
 * @param bufferLen the length of the destination buffer.
 * @param pDataLen the length of the return buffer.
*/
STATUS ioBufferRead(PIOBuffer pBuffer, PBYTE pData, UINT32 bufferLen, PUINT32 pDataLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 dataLen;

    CHK(pBuffer != NULL && pDataLen != NULL, STATUS_NULL_ARG);
    /**
     * #YC_TBD, this mechansim needs to be reviewed since it is not efficient.
     * #memory.
    */
    dataLen = MIN(bufferLen, pBuffer->len - pBuffer->off);
    
    MEMCPY(pData, pBuffer->raw + pBuffer->off, dataLen);
    pBuffer->off += dataLen;

    if (pBuffer->off == pBuffer->len) {
        ioBufferReset(pBuffer);
    }

    *pDataLen = dataLen;

CleanUp:

    return retStatus;
}
