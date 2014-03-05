#include <strings.h>

#include <openssl/sha.h>

#include <ts/ts.h>

/* Implement TS_HTTP_READ_RESPONSE_HDR_HOOK to implement a null transform.
 * Compute the SHA-256 digest of the content, write it to the cache and store
 * the request URL at that key.
 *
 * Implement TS_HTTP_SEND_RESPONSE_HDR_HOOK to check the "Location: ..." and
 * "Digest: SHA-256=..." headers.  Use TSCacheRead() to check if the URL in the
 * "Location: ..." header is already cached.  If not, potentially rewrite that
 * header.  Do this after responses are cached because the cache will change.
 *
 * More details are on the [wiki page] in the Traffic Server wiki.
 *
 * [wiki page]  https://cwiki.apache.org/confluence/display/TS/Metalink */

/* TSCacheWrite() and TSVConnWrite() data: Write the digest to the cache and
 * store the request URL at that key */

typedef struct {
  TSHttpTxn txnp;

  TSCacheKey key;

  TSVConn connp;
  TSIOBuffer cache_bufp;

} WriteData;

/* TSTransformCreate() data: Compute the SHA-256 digest of the content */

typedef struct {
  TSHttpTxn txnp;

  /* Null transform */
  TSIOBuffer output_bufp;
  TSVIO output_viop;

  /* Message digest handle */
  SHA256_CTX c;

} TransformData;

/* TSCacheRead() and TSVConnRead() data: Check the "Location: ..." and
 * "Digest: SHA-256=..." headers */

typedef struct {
  TSHttpTxn txnp;

  TSMBuffer resp_bufp;
  TSMLoc hdr_loc;

  /* "Location: ..." header */
  TSMLoc location_loc;

  /* Cache key */
  TSMLoc url_loc;
  TSCacheKey key;

  /* "Digest: SHA-256=..." header */
  TSMLoc digest_loc;

  /* Digest header field value index */
  int idx;

  TSIOBuffer cache_bufp;

} SendData;

/* Implement TS_HTTP_READ_RESPONSE_HDR_HOOK to implement a null transform */

/* Write the digest to the cache and store the request URL at that key */

static int
cache_open_write(TSCont contp, void *edata)
{
  TSMBuffer req_bufp;

  TSMLoc hdr_loc;
  TSMLoc url_loc;

  const char *value;
  int length;

  WriteData *data = (WriteData *) TSContDataGet(contp);
  data->connp = (TSVConn) edata;

  TSCacheKeyDestroy(data->key);

  if (TSHttpTxnClientReqGet(data->txnp, &req_bufp, &hdr_loc) != TS_SUCCESS) {
    TSError("Couldn't retrieve client request header");

    TSContDestroy(contp);

    TSfree(data);

    return 0;
  }

  if (TSHttpHdrUrlGet(req_bufp, hdr_loc, &url_loc) != TS_SUCCESS) {
    TSContDestroy(contp);

    TSfree(data);

    TSHandleMLocRelease(req_bufp, TS_NULL_MLOC, hdr_loc);

    return 0;
  }

  value = TSUrlStringGet(req_bufp, url_loc, &length);
  if (!value) {
    TSContDestroy(contp);

    TSfree(data);

    TSHandleMLocRelease(req_bufp, hdr_loc, url_loc);
    TSHandleMLocRelease(req_bufp, TS_NULL_MLOC, hdr_loc);

    return 0;
  }

  TSHandleMLocRelease(req_bufp, hdr_loc, url_loc);
  TSHandleMLocRelease(req_bufp, TS_NULL_MLOC, hdr_loc);

  /* Store the request URL */

  data->cache_bufp = TSIOBufferCreate();
  TSIOBufferReader readerp = TSIOBufferReaderAlloc(data->cache_bufp);

  int nbytes = TSIOBufferWrite(data->cache_bufp, value, length);

  /* Reuse the TSCacheWrite() continuation */
  TSVConnWrite(data->connp, contp, readerp, nbytes);

  return 0;
}

/* Do nothing */

static int
cache_open_write_failed(TSCont contp, void */* edata ATS_UNUSED */)
{
  WriteData *data = (WriteData *) TSContDataGet(contp);
  TSContDestroy(contp);

  TSCacheKeyDestroy(data->key);
  TSfree(data);

  return 0;
}

static int
write_vconn_write_complete(TSCont contp, void */* edata ATS_UNUSED */)
{
  WriteData *data = (WriteData *) TSContDataGet(contp);
  TSContDestroy(contp);

  /* The object is not committed to the cache until the vconnection is closed.
   * When all the data has been transferred, the user (contp) must do a
   * TSVConnClose() */
  TSVConnClose(data->connp);

  TSIOBufferDestroy(data->cache_bufp);
  TSfree(data);

  return 0;
}

/* TSCacheWrite() and TSVConnWrite() handler: Write the digest to the cache and
 * store the request URL at that key */

static int
write_handler(TSCont contp, TSEvent event, void *edata)
{
  switch (event) {
  case TS_EVENT_CACHE_OPEN_WRITE:
    return cache_open_write(contp, edata);

  case TS_EVENT_CACHE_OPEN_WRITE_FAILED:
    return cache_open_write_failed(contp, edata);

  case TS_EVENT_VCONN_WRITE_COMPLETE:
    return write_vconn_write_complete(contp, edata);

  default:
    TSAssert(!"Unexpected event");
  }

  return 0;
}

/* Copy content from the input buffer to the output buffer without modification
 * and feed it to the message digest at the same time.
 *
 *   1. Check if any more content is possible before doing anything else to
 *      avoid failed asserts.
 *   2. Then deal with any content that is available now.
 *   3. Check if the content is complete after dealing with any available
 *      content in case that was the last of it.  If complete, do any
 *      bookkeeping that downstream needs and finish computing the digest.
 *      Otherwise either wait for more content or abort if no more content is
 *      possible.
 *
 * Events are sent from downstream and don't communicate the state of the input
 * (TS_EVENT_VCONN_WRITE_READY, TS_EVENT_VCONN_WRITE_COMPLETE, and
 * TS_EVENT_IMMEDIATE?) Clean up the output buffer on
 * TS_EVENT_VCONN_WRITE_COMPLETE and not before.
 *
 * Gather the state of the input from TSVIONTodoGet() and TSVIOReaderGet().
 * TSVIOReaderGet() is NULL when no more content is possible and the content is
 * complete only when TSVIONTodoGet() is zero.  Handle the end of the input
 * independently from the TS_EVENT_VCONN_WRITE_COMPLETE event from downstream. */

static int
vconn_write_ready(TSCont contp, void */* edata ATS_UNUSED */)
{
  const char *value;
  int64_t length;

  char digest[32];

  TransformData *transform_data = (TransformData *) TSContDataGet(contp);

  TSVIO input_viop = TSVConnWriteVIOGet(contp);

  /* Initialize data here because can't call TSVConnWrite() before
   * TS_HTTP_RESPONSE_TRANSFORM_HOOK */
  if (!transform_data->output_bufp) {

    /* Avoid failed assert "sdk_sanity_check_iocore_structure(connp) ==
     * TS_SUCCESS" in TSVConnWrite() if the response is 304 Not Modified */
    TSVConn output_connp = TSTransformOutputVConnGet(contp);
    if (!output_connp) {
      TSContDestroy(contp);

      TSfree(transform_data);

      return 0;
    }

    transform_data->output_bufp = TSIOBufferCreate();
    TSIOBufferReader readerp = TSIOBufferReaderAlloc(transform_data->output_bufp);

    /* Determines the "Content-Length: ..." header
     * (or "Transfer-Encoding: chunked") */

    /* Avoid failed assert "nbytes >= 0" if "Transfer-Encoding: chunked" */
    int nbytes = TSVIONBytesGet(input_viop);
    transform_data->output_viop = TSVConnWrite(output_connp, contp, readerp, nbytes < 0 ? INT64_MAX : nbytes);

    SHA256_Init(&transform_data->c);
  }

  /* Avoid failed assert "sdk_sanity_check_iocore_structure(readerp) ==
   * TS_SUCCESS" in TSIOBufferReaderAvail() if the client or server disconnects
   * or the content length is zero */
  TSIOBufferReader readerp = TSVIOReaderGet(input_viop);
  if (readerp) {

    int avail = TSIOBufferReaderAvail(readerp);
    if (avail) {
      TSIOBufferCopy(transform_data->output_bufp, readerp, avail, 0);

      /* Feed content to the message digest */
      TSIOBufferBlock blockp = TSIOBufferReaderStart(readerp);
      while (blockp) {

        value = TSIOBufferBlockReadStart(blockp, readerp, &length);
        SHA256_Update(&transform_data->c, value, length);

        blockp = TSIOBufferBlockNext(blockp);
      }

      TSIOBufferReaderConsume(readerp, avail);

      /* Call TSVIONDoneSet() for TSVIONTodoGet() condition */
      int ndone = TSVIONDoneGet(input_viop);
      TSVIONDoneSet(input_viop, ndone + avail);
    }
  }

  int ntodo = TSVIONTodoGet(input_viop);
  if (ntodo) {

    /* Don't update the downstream nbytes and reenable it because the content
     * isn't complete */
    if (!readerp) {
      TSContDestroy(contp);

      TSIOBufferDestroy(transform_data->output_bufp);
      TSfree(transform_data);

      return 0;
    }

    TSVIOReenable(transform_data->output_viop);

    TSContCall(TSVIOContGet(input_viop), TS_EVENT_VCONN_WRITE_READY, input_viop);

  } else {

    int ndone = TSVIONDoneGet(input_viop);
    TSVIONBytesSet(transform_data->output_viop, ndone);

    TSVIOReenable(transform_data->output_viop);

    /* Write the digest to the cache */

    SHA256_Final((unsigned char *) digest, &transform_data->c);

    WriteData *write_data = (WriteData *) TSmalloc(sizeof(WriteData));
    write_data->txnp = transform_data->txnp;

    write_data->key = TSCacheKeyCreate();
    if (TSCacheKeyDigestSet(write_data->key, digest, sizeof(digest)) != TS_SUCCESS) {

      TSCacheKeyDestroy(write_data->key);
      TSfree(write_data);

      return 0;
    }

    /* Can't reuse the TSTransformCreate() continuation because don't know
     * whether to destroy it in cache_open_write()/cache_open_write_failed() or
     * transform_vconn_write_complete() */
    contp = TSContCreate(write_handler, NULL);
    TSContDataSet(contp, write_data);

    TSCacheWrite(contp, write_data->key);
  }

  return 0;
}

static int
transform_vconn_write_complete(TSCont contp, void */* edata ATS_UNUSED */)
{
  TransformData *data = (TransformData *) TSContDataGet(contp);
  TSContDestroy(contp);

  TSIOBufferDestroy(data->output_bufp);
  TSfree(data);

  return 0;
}

/* TSTransformCreate() handler: Compute the SHA-256 digest of the content */

static int
transform_handler(TSCont contp, TSEvent event, void *edata)
{
  switch (event) {
  case TS_EVENT_IMMEDIATE:
  case TS_EVENT_VCONN_WRITE_READY:
    return vconn_write_ready(contp, edata);

  case TS_EVENT_VCONN_WRITE_COMPLETE:
    return transform_vconn_write_complete(contp, edata);

  default:
    TSAssert(!"Unexpected event");
  }

  return 0;
}

/* Compute the SHA-256 digest of the content, write it to the cache and store
 * the request URL at that key */

static int
http_read_response_hdr(TSCont /* contp ATS_UNUSED */, void *edata)
{
  TransformData *data = (TransformData *) TSmalloc(sizeof(TransformData));
  data->txnp = (TSHttpTxn) edata;

  /* Can't initialize data here because can't call TSVConnWrite() before
   * TS_HTTP_RESPONSE_TRANSFORM_HOOK */
  data->output_bufp = NULL;

  TSVConn connp = TSTransformCreate(transform_handler, data->txnp);
  TSContDataSet(connp, data);

  TSHttpTxnHookAdd(data->txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);

  TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);

  return 0;
}

/* Implement TS_HTTP_SEND_RESPONSE_HDR_HOOK to check the "Location: ..." and
 * "Digest: SHA-256=..." headers */

/* Read the URL stored at the digest */

static int
cache_open_read(TSCont contp, void *edata)
{
  SendData *data = (SendData *) TSContDataGet(contp);

  TSVConn connp = (TSVConn) edata;

  data->cache_bufp = TSIOBufferCreate();

  /* Reuse the TSCacheRead() continuation */
  TSVConnRead(connp, contp, data->cache_bufp, INT64_MAX);

  return 0;
}

/* Do nothing, just reenable the response */

static int
cache_open_read_failed(TSCont contp, void */* edata ATS_UNUSED */)
{
  SendData *data = (SendData *) TSContDataGet(contp);
  TSContDestroy(contp);

  TSCacheKeyDestroy(data->key);

  TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->url_loc);
  TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->location_loc);
  TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->hdr_loc);

  TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
  TSfree(data);

  return 0;
}

/* TSCacheRead() handler: Check if the URL stored at the digest is cached */

static int
rewrite_handler(TSCont contp, TSEvent event, void */* edata ATS_UNUSED */)
{
  const char *value;
  int length;

  SendData *data = (SendData *) TSContDataGet(contp);
  TSContDestroy(contp);

  switch (event) {

  /* Yes: Rewrite the "Location: ..." header and reenable the response */
  case TS_EVENT_CACHE_OPEN_READ:
    value = TSUrlStringGet(data->resp_bufp, data->url_loc, &length);

    TSMimeHdrFieldValuesClear(data->resp_bufp, data->hdr_loc, data->location_loc);
    TSMimeHdrFieldValueStringInsert(data->resp_bufp, data->hdr_loc, data->location_loc, -1, value, length);

    break;

  /* No: Do nothing, just reenable the response */
  case TS_EVENT_CACHE_OPEN_READ_FAILED:
    break;

  default:
    TSAssert(!"Unexpected event");
  }

  TSCacheKeyDestroy(data->key);

  TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->url_loc);
  TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->location_loc);
  TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->hdr_loc);

  TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
  TSfree(data);

  return 0;
}

/* Read the URL stored at the digest */

static int
vconn_read_ready(TSCont contp, void */* edata ATS_UNUSED */)
{
  const char *value;
  int64_t length;

  SendData *data = (SendData *) TSContDataGet(contp);
  TSContDestroy(contp);

  TSIOBufferReader readerp = TSIOBufferReaderAlloc(data->cache_bufp);

  TSIOBufferBlock blockp = TSIOBufferReaderStart(readerp);

  value = TSIOBufferBlockReadStart(blockp, readerp, &length);
  if (TSUrlParse(data->resp_bufp, data->url_loc, &value, value + length) != TS_PARSE_DONE) {
    TSIOBufferDestroy(data->cache_bufp);

    TSCacheKeyDestroy(data->key);

    TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->url_loc);
    TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->location_loc);
    TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->hdr_loc);

    TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
    TSfree(data);

    return 0;
  }

  TSIOBufferDestroy(data->cache_bufp);

  if (TSCacheKeyDigestFromUrlSet(data->key, data->url_loc) != TS_SUCCESS) {
    TSCacheKeyDestroy(data->key);

    TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->url_loc);
    TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->location_loc);
    TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->hdr_loc);

    TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
    TSfree(data);

    return 0;
  }

  /* Check if the URL stored at the digest is cached */

  contp = TSContCreate(rewrite_handler, NULL);
  TSContDataSet(contp, data);

  TSCacheRead(contp, data->key);

  return 0;
}

/* TSCacheRead() and TSVConnRead() handler: Check if the "Digest: SHA-256=..."
 * digest already exists in the cache */

static int
digest_handler(TSCont contp, TSEvent event, void *edata)
{
  switch (event) {

  /* Yes: Read the URL stored at that key */
  case TS_EVENT_CACHE_OPEN_READ:
    return cache_open_read(contp, edata);

  /* No: Do nothing, just reenable the response */
  case TS_EVENT_CACHE_OPEN_READ_FAILED:
    return cache_open_read_failed(contp, edata);

  case TS_EVENT_VCONN_READ_READY:
    return vconn_read_ready(contp, edata);

  default:
    TSAssert(!"Unexpected event");
  }

  return 0;
}

/* TSCacheRead() handler: Check if the "Location: ..." URL is already cached */

static int
location_handler(TSCont contp, TSEvent event, void */* edata ATS_UNUSED */)
{
  const char *value;
  int length;

  /* ATS_BASE64_DECODE_DSTLEN() */
  char digest[33];

  SendData *data = (SendData *) TSContDataGet(contp);
  TSContDestroy(contp);

  switch (event) {

  /* Yes: Do nothing, just reenable the response */
  case TS_EVENT_CACHE_OPEN_READ:
    break;

  /* No: Check if the "Digest: SHA-256=..." digest already exists in the cache */
  case TS_EVENT_CACHE_OPEN_READ_FAILED:

    value = TSMimeHdrFieldValueStringGet(data->resp_bufp, data->hdr_loc, data->digest_loc, data->idx, &length);
    if (TSBase64Decode(value + 8, length - 8, (unsigned char *) digest, sizeof(digest), NULL) != TS_SUCCESS
        || TSCacheKeyDigestSet(data->key, digest, 32 /* SHA-256 */ ) != TS_SUCCESS) {
      break;
    }

    contp = TSContCreate(digest_handler, NULL);
    TSContDataSet(contp, data);

    TSCacheRead(contp, data->key);

    TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->digest_loc);

    return 0;

  default:
    TSAssert(!"Unexpected event");
  }

  TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->digest_loc);

  TSCacheKeyDestroy(data->key);

  TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->url_loc);
  TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->location_loc);
  TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->hdr_loc);

  TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
  TSfree(data);

  return 0;
}

/* Use TSCacheRead() to check if the URL in the "Location: ..." header is
 * already cached.  If not, potentially rewrite that header.  Do this after
 * responses are cached because the cache will change. */

static int
http_send_response_hdr(TSCont contp, void *edata)
{
  const char *value;
  int length;

  SendData *data = (SendData *) TSmalloc(sizeof(SendData));
  data->txnp = (TSHttpTxn) edata;

  if (TSHttpTxnClientRespGet(data->txnp, &data->resp_bufp, &data->hdr_loc) != TS_SUCCESS) {
    TSError("Couldn't retrieve client response header");

    TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
    TSfree(data);

    return 0;
  }

  /* If Instance Digests are not provided by the Metalink servers, the Link
   * header fields pertaining to this specification MUST be ignored */

  /* Metalinks contain whole file hashes as described in Section 6, and MUST
   * include SHA-256, as specified in [FIPS-180-3] */

  /* Assumption: Want to minimize cache read, so check first that:
   *
   *   1. response has a "Location: ..." header
   *   2. response has a "Digest: SHA-256=..." header
   *
   * Then scan if the URL or digest already exist in the cache */

  /* If the response has a "Location: ..." header */
  data->location_loc = TSMimeHdrFieldFind(data->resp_bufp, data->hdr_loc, TS_MIME_FIELD_LOCATION, TS_MIME_LEN_LOCATION);
  if (!data->location_loc) {
    TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->hdr_loc);

    TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
    TSfree(data);

    return 0;
  }

  TSUrlCreate(data->resp_bufp, &data->url_loc);

  /* If can't parse or lookup the "Location: ..." URL, should still check if
   * the response has a "Digest: SHA-256=..." header?  No: Can't parse or
   * lookup the URL in the "Location: ..." header is an error. */
  value = TSMimeHdrFieldValueStringGet(data->resp_bufp, data->hdr_loc, data->location_loc, -1, &length);
  if (TSUrlParse(data->resp_bufp, data->url_loc, &value, value + length) != TS_PARSE_DONE) {

    TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->url_loc);
    TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->location_loc);
    TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->hdr_loc);

    TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
    TSfree(data);

    return 0;
  }

  data->key = TSCacheKeyCreate();
  if (TSCacheKeyDigestFromUrlSet(data->key, data->url_loc) != TS_SUCCESS) {
    TSCacheKeyDestroy(data->key);

    TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->url_loc);
    TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->location_loc);
    TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->hdr_loc);

    TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
    TSfree(data);

    return 0;
  }

  /* ... and a "Digest: SHA-256=..." header */
  data->digest_loc = TSMimeHdrFieldFind(data->resp_bufp, data->hdr_loc, "Digest", 6);
  while (data->digest_loc) {

    int count = TSMimeHdrFieldValuesCount(data->resp_bufp, data->hdr_loc, data->digest_loc);
    for (data->idx = 0; data->idx < count; data->idx += 1) {

      value = TSMimeHdrFieldValueStringGet(data->resp_bufp, data->hdr_loc, data->digest_loc, data->idx, &length);
      if (length < 8 + 44 /* 32 bytes, Base64 */ || strncasecmp(value, "SHA-256=", 8)) {
        continue;
      }

      /* Check if the "Location: ..." URL is already cached */

      contp = TSContCreate(location_handler, NULL);
      TSContDataSet(contp, data);

      TSCacheRead(contp, data->key);

      return 0;
    }

    TSMLoc next_loc = TSMimeHdrFieldNextDup(data->resp_bufp, data->hdr_loc, data->digest_loc);

    TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->digest_loc);

    data->digest_loc = next_loc;
  }

  /* Didn't find a "Digest: SHA-256=..." header, just reenable the response */

  TSCacheKeyDestroy(data->key);

  TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->url_loc);
  TSHandleMLocRelease(data->resp_bufp, data->hdr_loc, data->location_loc);
  TSHandleMLocRelease(data->resp_bufp, TS_NULL_MLOC, data->hdr_loc);

  TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
  TSfree(data);

  return 0;
}

static int
handler(TSCont contp, TSEvent event, void *edata)
{
  switch (event) {
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    return http_read_response_hdr(contp, edata);

  case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
    return http_send_response_hdr(contp, edata);

  default:
    TSAssert(!"Unexpected event");
  }

  return 0;
}

void
TSPluginInit(int /* argc ATS_UNUSED */, const char */* argv ATS_UNUSED */[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name = const_cast<char *>("metalink");
  info.vendor_name = const_cast<char *>("Jack Bates");
  info.support_email = const_cast<char *>("jack@nottheoilrig.com");

  if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
    TSError("Plugin registration failed");
  }

  TSCont contp = TSContCreate(handler, NULL);

  TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
  TSHttpHookAdd(TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
}
