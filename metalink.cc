#include <stdio.h>
#include <string.h>

#include <gcrypt.h>

#define __STDC_LIMIT_MACROS

#include <ts/ts.h>

typedef struct {

  TSIOBuffer bufp;

} WriteData;

typedef struct {

  TSHttpTxn txnp;

  /* Null transform */
  TSIOBuffer bufp;
  TSVIO viop;

  /* Message digest handle */
  gcry_md_hd_t hd;

  TSCacheKey key;

} TransformData;

typedef struct {

  TSHttpTxn txnp;
  TSMBuffer bufp;
  TSMLoc hdr_loc;

  /* "Location: ..." header */
  TSMLoc location_loc;

  /* Cache key */
  TSMLoc url_loc;
  TSCacheKey key;

  /* RFC 6249 "Link: <...>; rel=duplicate" header */
  TSMLoc link_loc;

  /* Link header field value index */
  int idx;

} SendData;

static int
write_vconn_write_complete(TSCont contp, void *edata)
{
  WriteData *data = (WriteData *) TSContDataGet(contp);

  TSIOBufferDestroy(data->bufp);
  TSfree(data);

  TSContDestroy(contp);

  return 0;
}

static int
write_handler(TSCont contp, TSEvent event, void *edata)
{
  switch (event) {
  case TS_EVENT_VCONN_WRITE_COMPLETE:
    return write_vconn_write_complete(contp, edata);

  default:
    TSAssert(!"Unexpected event");
  }

  return 0;
}

static int
cache_open_write(TSCont contp, void *edata)
{
  TSMBuffer bufp;

  TSMLoc hdr_loc;
  TSMLoc url_loc;

  const char *value;
  int length;

  TransformData *transform_data = (TransformData *) TSContDataGet(contp);

  TSCacheKeyDestroy(transform_data->key);

  TSVConn connp = (TSVConn) edata;

  contp = TSContCreate(write_handler, NULL);

  WriteData *write_data = (WriteData *) TSmalloc(sizeof(WriteData));
  TSContDataSet(contp, write_data);

  write_data->bufp = TSIOBufferCreate();
  TSIOBufferReader readerp = TSIOBufferReaderAlloc(write_data->bufp);

  if (TSHttpTxnClientReqGet(transform_data->txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    TSError("Couldn't retrieve client request header");

    return 0;
  }

  if (TSHttpHdrUrlGet(bufp, hdr_loc, &url_loc) != TS_SUCCESS) {
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);

    return 0;
  }

  value = TSUrlStringGet(bufp, url_loc, &length);
  if (!value) {

    TSHandleMLocRelease(bufp, hdr_loc, url_loc);
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);

    return 0;
  }

  TSHandleMLocRelease(bufp, hdr_loc, url_loc);
  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);

  int nbytes = TSIOBufferWrite(write_data->bufp, value, length);

  TSVConnWrite(connp, contp, readerp, nbytes);

  return 0;
}

static int
cache_open_write_failed(TSCont contp, void *edata)
{
  TransformData *data = (TransformData *) TSContDataGet(contp);

  TSCacheKeyDestroy(data->key);

  return 0;
}

static int
vconn_write_ready(TSCont contp, void *edata)
{
  const char *value;
  int64_t length;

  TransformData *data = (TransformData *) TSContDataGet(contp);

  /* Can't TSVConnWrite() before TS_HTTP_RESPONSE_TRANSFORM_HOOK */
  if (!data->bufp) {
    TSVConn connp = TSTransformOutputVConnGet(contp);

    data->bufp = TSIOBufferCreate();
    TSIOBufferReader readerp = TSIOBufferReaderAlloc(data->bufp);

    data->viop = TSVConnWrite(connp, contp, readerp, INT64_MAX);

    gcry_md_open(&data->hd, GCRY_MD_SHA256, NULL);
  }

  TSVIO viop = TSVConnWriteVIOGet(contp);

  TSIOBuffer bufp = TSVIOBufferGet(viop);
  if (!bufp) {
    int ndone = TSVIONDoneGet(viop);
    TSVIONBytesSet(data->viop, ndone);

    TSVIOReenable(data->viop);

    return 0;
  }

  TSIOBufferReader readerp = TSVIOReaderGet(viop);

  int avail = TSIOBufferReaderAvail(readerp);
  if (avail > 0) {
    TSIOBufferCopy(data->bufp, readerp, avail, 0);

    /* Feed content to message digest */
    TSIOBufferBlock blockp = TSIOBufferReaderStart(readerp);
    while (blockp) {

      value = TSIOBufferBlockReadStart(blockp, readerp, &length);
      gcry_md_write(data->hd, value, length);

      blockp = TSIOBufferBlockNext(blockp);
    }

    TSIOBufferReaderConsume(readerp, avail);

    int ndone = TSVIONDoneGet(viop);
    TSVIONDoneSet(viop, ndone + avail);
  }

  /* If not finished and we copied some content */
  int ntodo = TSVIONTodoGet(viop);
  if (ntodo > 0) {
    if (avail > 0) {
      TSContCall(TSVIOContGet(viop), TS_EVENT_VCONN_WRITE_READY, viop);

      TSVIOReenable(data->viop);
    }

  /* If finished */
  } else {
    TSContCall(TSVIOContGet(viop), TS_EVENT_VCONN_WRITE_COMPLETE, viop);

    int ndone = TSVIONDoneGet(viop);
    TSVIONBytesSet(data->viop, ndone);

    TSVIOReenable(data->viop);

    value = (char *) gcry_md_read(data->hd, NULL);

    data->key = TSCacheKeyCreate();
    if (TSCacheKeyDigestSet(data->key, value, 32) != TS_SUCCESS) {
      gcry_md_close(data->hd);

      return 0;
    }

    TSCacheWrite(contp, data->key);

    gcry_md_close(data->hd);
  }

  return 0;
}

static int
transform_vconn_write_complete(TSCont contp, void *edata)
{
  TransformData *data = (TransformData *) TSContDataGet(contp);

  TSVConn connp = TSTransformOutputVConnGet(contp);
  TSVConnShutdown(connp, 0, 1);

  TSIOBufferDestroy(data->bufp);
  TSfree(data);

  TSContDestroy(contp);

  return 0;
}

static int
transform_handler(TSCont contp, TSEvent event, void *edata)
{
  switch (event) {
  case TS_EVENT_CACHE_OPEN_WRITE:
    return cache_open_write(contp, edata);

  case TS_EVENT_CACHE_OPEN_WRITE_FAILED:
    return cache_open_write_failed(contp, edata);

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

static bool
rel_duplicate(const char *value, const char *end)
{
  while (value + 13 /* rel=duplicate */ < end) {

    value += 1;
    value += strspn(value, " ");

    if (strncmp(value, "rel=", 4)) {

      value = strchr(value, '=');
      if (!value) {
        return false;
      }

      value += 1;

      /* quoted-string */
      if (*value == '"') {

        for (value += 1;;) {

          value += strcspn(value, "\\\"");
          if (*value == '"') {
            value += 1;

            break; // continue 2;
          }

          value += 2;
          if (value + 15 /* ";rel=duplicate */ >= end) {
            return false;
          }
        }

      /* ptoken */
      } else {

        value = strchr(value, ';');
        if (!value) {
          return false;
        }
      }

      continue;
    }

    value += 4;

    /* <"> relation-type *( 1*SP relation-type ) <"> */
    if (*value == '"') {

      for (value += 1;;) {

        int length = strcspn(value, " \"");
        if (strncmp(value, "duplicate", length)) {

          value += length;
          if (*value == '"') {
            value += 1;

            break; // continue 2;
          }

          value += 1;
          if (value + 15 /* ";rel=duplicate */ >= end) {
            return false;
          }
        }

        return true;
      }

    /* relation-type */
    } else {

      int length = strcspn(value, ";");
      if (strncmp(value, "duplicate", length)) {
        value += 1;

        continue;
      }

      return true;
    }
  }

  return false;
}

/* Check if RFC 6249 "Link: <...>; rel=duplicate" URL already exist in cache */

static int
link_handler(TSCont contp, TSEvent event, void *edata)
{
  const char *value;
  int length;

  SendData *data = (SendData *) TSContDataGet(contp);

  switch (event) {

  /* Yes: Update "Location: ..." header and reenable response */
  case TS_EVENT_CACHE_OPEN_READ:
    TSHandleMLocRelease(data->bufp, data->hdr_loc, data->link_loc);

    value = TSUrlStringGet(data->bufp, data->url_loc, &length);

    TSMimeHdrFieldValuesClear(data->bufp, data->hdr_loc, data->location_loc);
    TSMimeHdrFieldValueStringInsert(data->bufp, data->hdr_loc, data->location_loc, -1, value, length);

    break;

  /* No: Check next RFC 6249 "Link: <...>; rel=duplicate" URL */
  case TS_EVENT_CACHE_OPEN_READ_FAILED:

    data->idx += 1;
    do {

      int count = TSMimeHdrFieldValuesCount(data->bufp, data->hdr_loc, data->link_loc);
      for (; data->idx < count; data->idx += 1) {
        value = TSMimeHdrFieldValueStringGet(data->bufp, data->hdr_loc, data->link_loc, data->idx, &length);

        /* "string values returned from marshall buffers are not
         * null-terminated.  If you need a null-terminated value, then use
         * TSstrndup to automatically null-terminate a string",
         * http://trafficserver.apache.org/docs/trunk/sdk/http-headers/guide-to-trafficserver-http-header-system/index.en.html */
        value = TSstrndup(value, length);

        /* link-value = "<" URI-Reference ">" *( ";" link-param ) ; RFC 5988 */
        const char *start = value + 1;

        const char *end = strchr(start, '>');
        if (!end || !rel_duplicate(end + 1, value + length)
            || TSUrlParse(data->bufp, data->url_loc, &start, end) != TS_PARSE_DONE
            || TSCacheKeyDigestFromUrlSet(data->key, data->url_loc) != TS_SUCCESS) {
          continue;
        }

        TSCacheRead(contp, data->key);

        return 0;
      }

      TSMLoc next_loc = TSMimeHdrFieldNextDup(data->bufp, data->hdr_loc, data->link_loc);

      TSHandleMLocRelease(data->bufp, data->hdr_loc, data->link_loc);

      data->link_loc = next_loc;
      data->idx = 0;

    } while (data->link_loc);

    break;

  default:
    TSAssert(!"Unexpected event");
  }

  TSCacheKeyDestroy(data->key);

  TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->url_loc);
  TSHandleMLocRelease(data->bufp, data->hdr_loc, data->location_loc);
  TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->hdr_loc);

  TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
  TSfree(data);

  TSContDestroy(contp);

  return 0;
}

/* Check if "Location: ..." URL already exist in cache */

static int
location_handler(TSCont contp, TSEvent event, void *edata)
{
  SendData *data = (SendData *) TSContDataGet(contp);

  TSContDestroy(contp);

  switch (event) {

  /* Yes: Do nothing, just reenable response */
  case TS_EVENT_CACHE_OPEN_READ:
    break;

  /* No: Check RFC 6249 "Link: <...>; rel=duplicate" URL */
  case TS_EVENT_CACHE_OPEN_READ_FAILED:

    const char *value;
    int length;

    const char *start;
    const char *end;

    value = TSMimeHdrFieldValueStringGet(data->bufp, data->hdr_loc, data->link_loc, data->idx, &length);

    /* link-value = "<" URI-Reference ">" *( ";" link-param ) ; RFC 5988 */
    start = value + 1;

    /* memchr() vs. strchr() because "not null-terminated cannot be passed into
     * the common str*() routines",
     * http://trafficserver.apache.org/docs/trunk/sdk/http-headers/guide-to-trafficserver-http-header-system/index.en.html */
    end = (char *) memchr(start, '>', length - 1);
    if (!end
        || TSUrlParse(data->bufp, data->url_loc, &start, end) != TS_PARSE_DONE
        || TSCacheKeyDigestFromUrlSet(data->key, data->url_loc) != TS_SUCCESS) {
      contp = TSContCreate(link_handler, NULL);
      TSContDataSet(contp, data);

      link_handler(contp, TS_EVENT_CACHE_OPEN_READ_FAILED, NULL);

      return 0;
    }

    contp = TSContCreate(link_handler, NULL);
    TSContDataSet(contp, data);

    TSCacheRead(contp, data->key);

    return 0;

  default:
    TSAssert(!"Unexpected event");
  }

  TSHandleMLocRelease(data->bufp, data->hdr_loc, data->link_loc);

  TSCacheKeyDestroy(data->key);

  TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->url_loc);
  TSHandleMLocRelease(data->bufp, data->hdr_loc, data->location_loc);
  TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->hdr_loc);

  TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
  TSfree(data);

  return 0;
}

static int
http_read_response_hdr(TSCont contp, void *edata)
{
  TransformData *data = (TransformData *) TSmalloc(sizeof(TransformData));
  data->txnp = (TSHttpTxn) edata;

  data->bufp = NULL;

  TSVConn connp = TSTransformCreate(transform_handler, data->txnp);
  TSContDataSet(connp, data);

  TSHttpTxnHookAdd(data->txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);

  TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);

  return 0;
}

static int
http_send_response_hdr(TSCont contp, void *edata)
{
  const char *value;
  int length;

  SendData *data = (SendData *) TSmalloc(sizeof(SendData));
  data->txnp = (TSHttpTxn) edata;

  if (TSHttpTxnClientRespGet(data->txnp, &data->bufp, &data->hdr_loc) != TS_SUCCESS) {
    TSError("Couldn't retrieve client response header");

    TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
    TSfree(data);

    return 0;
  }

  /* Assumption: Want to minimize cache read, so check first that:
   *
   *   1. response has "Location: ..." header
   *   2. response has RFC 6249 "Link: <...>; rel=duplicate" header
   *
   * Then scan if URL already exist in cache */

  /* If response has "Location: ..." header */
  data->location_loc = TSMimeHdrFieldFind(data->bufp, data->hdr_loc, TS_MIME_FIELD_LOCATION, TS_MIME_LEN_LOCATION);
  if (!data->location_loc) {
    TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->hdr_loc);

    TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
    TSfree(data);

    return 0;
  }

  value = TSMimeHdrFieldValueStringGet(data->bufp, data->hdr_loc, data->location_loc, 0, &length);

  /* If can't parse or lookup "Location: ..." URL, should still check if
   * response has RFC 6249 "Link: <...>; rel=duplicate" header? No: Can't
   * parse or lookup URL in "Location: ..." header is error */
  TSUrlCreate(data->bufp, &data->url_loc);
  if (TSUrlParse(data->bufp, data->url_loc, &value, value + length) != TS_PARSE_DONE) {

    TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->url_loc);
    TSHandleMLocRelease(data->bufp, data->hdr_loc, data->location_loc);
    TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->hdr_loc);

    TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
    TSfree(data);

    return 0;
  }

  data->key = TSCacheKeyCreate();
  if (TSCacheKeyDigestFromUrlSet(data->key, data->url_loc) != TS_SUCCESS) {
    TSCacheKeyDestroy(data->key);

    TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->url_loc);
    TSHandleMLocRelease(data->bufp, data->hdr_loc, data->location_loc);
    TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->hdr_loc);

    TSHttpTxnReenable(data->txnp, TS_EVENT_HTTP_CONTINUE);
    TSfree(data);

    return 0;
  }

  /* ... and RFC 6249 "Link: <...>; rel=duplicate" header */
  data->link_loc = TSMimeHdrFieldFind(data->bufp, data->hdr_loc, "Link", 4);
  while (data->link_loc) {

    int count = TSMimeHdrFieldValuesCount(data->bufp, data->hdr_loc, data->link_loc);
    for (data->idx = 0; data->idx < count; data->idx += 1) {
      value = TSMimeHdrFieldValueStringGet(data->bufp, data->hdr_loc, data->link_loc, data->idx, &length);

      /* "string values returned from marshall buffers are not
       * null-terminated.  If you need a null-terminated value, then use
       * TSstrndup to automatically null-terminate a string",
       * http://trafficserver.apache.org/docs/trunk/sdk/http-headers/guide-to-trafficserver-http-header-system/index.en.html */
      value = TSstrndup(value, length);

      /* link-value = "<" URI-Reference ">" *( ";" link-param ) ; RFC 5988 */
      const char *start = value + 1;

      const char *end = strchr(start, '>');
      if (!end || !rel_duplicate(end + 1, value + length)) {
        continue;
      }

      contp = TSContCreate(location_handler, NULL);
      TSContDataSet(contp, data);

      TSCacheRead(contp, data->key);

      return 0;
    }

    TSMLoc next_loc = TSMimeHdrFieldNextDup(data->bufp, data->hdr_loc, data->link_loc);

    TSHandleMLocRelease(data->bufp, data->hdr_loc, data->link_loc);

    data->link_loc = next_loc;
  }

  TSCacheKeyDestroy(data->key);

  TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->url_loc);
  TSHandleMLocRelease(data->bufp, data->hdr_loc, data->location_loc);
  TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->hdr_loc);

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
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name = const_cast<char*>("metalink");
  info.vendor_name = const_cast<char*>("Jack Bates");
  info.support_email = const_cast<char*>("jack@nottheoilrig.com");

  if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
    TSError("Plugin registration failed");
  }

  TSCont contp = TSContCreate(handler, NULL);

  TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
  TSHttpHookAdd(TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
}
