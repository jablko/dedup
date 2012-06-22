#include <stdio.h>
#include <string.h>

#include <gcrypt.h>

#define __STDC_LIMIT_MACROS

#include <ts/ts.h>

typedef struct {

  /* Null transform */
  TSIOBuffer bufp;
  TSVIO viop;

  /* Message digest handle */
  gcry_md_hd_t hd;

} ReadData;

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
transform_handler(TSCont contp, TSEvent event, void *edata)
{
  ReadData *data = (ReadData *) TSContDataGet(contp);

  switch (event) {
  case TS_EVENT_IMMEDIATE:
  case TS_EVENT_VCONN_WRITE_READY:
    TSVIO viop;

    TSIOBuffer bufp;
    TSIOBufferReader readerp;

    int avail;

    TSIOBufferBlock blockp;

    const char *value;
    int64_t length;

    int ndone;
    int ntodo;

    /* Can't TSVConnWrite() before TS_HTTP_RESPONSE_TRANSFORM_HOOK */
    if (!data) {
      TSVConn connp = TSTransformOutputVConnGet(contp);

      data = (ReadData *) TSmalloc(sizeof(ReadData));
      TSContDataSet(contp, data);

      data->bufp = TSIOBufferCreate();
      readerp = TSIOBufferReaderAlloc(data->bufp);

      data->viop = TSVConnWrite(connp, contp, readerp, INT64_MAX);

      gcry_md_open(&data->hd, GCRY_MD_SHA256, NULL);
    }

    viop = TSVConnWriteVIOGet(contp);

    bufp = TSVIOBufferGet(viop);
    if (!bufp) {
      ndone = TSVIONDoneGet(viop);
      TSVIONBytesSet(data->viop, ndone);

      TSVIOReenable(data->viop);

      break;
    }

    readerp = TSVIOReaderGet(viop);

    avail = TSIOBufferReaderAvail(readerp);
    if (avail > 0) {
      TSIOBufferCopy(data->bufp, readerp, avail, 0);

      /* Feed content to message digest */
      blockp = TSIOBufferReaderStart(readerp);
      while (blockp) {

        value = TSIOBufferBlockReadStart(blockp, readerp, &length);
        gcry_md_write(data->hd, value, length);

        blockp = TSIOBufferBlockNext(blockp);
      }

      TSIOBufferReaderConsume(readerp, avail);

      ndone = TSVIONDoneGet(viop);
      TSVIONDoneSet(viop, ndone + avail);
    }

    /* If not finished and we copied some content */
    ntodo = TSVIONTodoGet(viop);
    if (ntodo > 0) {
      if (avail > 0) {
        TSContCall(TSVIOContGet(viop), TS_EVENT_VCONN_WRITE_READY, viop);

        TSVIOReenable(data->viop);
      }

    /* If finished */
    } else {
      TSContCall(TSVIOContGet(viop), TS_EVENT_VCONN_WRITE_COMPLETE, viop);

      ndone = TSVIONDoneGet(viop);
      TSVIONBytesSet(data->viop, ndone);

      TSVIOReenable(data->viop);

      gcry_md_read(data->hd, NULL);

      gcry_md_close(data->hd);
    }

    break;

  case TS_EVENT_VCONN_WRITE_COMPLETE:
    TSVConn connp;

    connp = TSTransformOutputVConnGet(contp);
    TSVConnShutdown(connp, 0, 1);

    TSIOBufferDestroy(data->bufp);

    TSfree(data);
    TSContDestroy(contp);

    break;

  default:
    TSAssert(!"Unexpected event");
  }

  return 0;
}

static bool
rel_duplicate(const char *value, const char *end)
{
  int length;

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

        length = strcspn(value, " \"");
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

      length = strcspn(value, ";");
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
  SendData *data = (SendData *) TSContDataGet(contp);

  const char *value;
  int length;

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
    TSMLoc next_loc;

    int count;

    const char *start;
    const char *end;

    data->idx += 1;
    do {

      count = TSMimeHdrFieldValuesCount(data->bufp, data->hdr_loc, data->link_loc);
      for (; data->idx < count; data->idx += 1) {
        value = TSMimeHdrFieldValueStringGet(data->bufp, data->hdr_loc, data->link_loc, data->idx, &length);

        /* "string values returned from marshall buffers are not
         * null-terminated.  If you need a null-terminated value, then use
         * TSstrndup to automatically null-terminate a string",
         * http://trafficserver.apache.org/docs/trunk/sdk/http-headers/guide-to-trafficserver-http-header-system/index.en.html */
        value = TSstrndup(value, length);

        /* link-value = "<" URI-Reference ">" *( ";" link-param ) ; RFC 5988 */
        start = value + 1;

        end = strchr(start, '>');
        if (!end || !rel_duplicate(end + 1, value + length)
            || TSUrlParse(data->bufp, data->url_loc, &start, end) != TS_PARSE_DONE
            || TSCacheKeyDigestFromUrlSet(data->key, data->url_loc) != TS_SUCCESS) {
          continue;
        }

        TSCacheRead(contp, data->key);

        return 0;
      }

      next_loc = TSMimeHdrFieldNextDup(data->bufp, data->hdr_loc, data->link_loc);

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
handler(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = (TSHttpTxn) edata;

  switch (event) {
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    TSVConn connp;

    connp = TSTransformCreate(transform_handler, txnp);
    TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);

    break;

  case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
    SendData *data;

    const char *value;
    int length;

    TSMLoc next_loc;

    int count;

    const char *start;
    const char *end;

    data = (SendData *) TSmalloc(sizeof(SendData));
    data->txnp = txnp;

    if (TSHttpTxnClientRespGet(txnp, &data->bufp, &data->hdr_loc) != TS_SUCCESS) {
      TSError("Couldn't retrieve client response header");

      TSfree(data);

      break;
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

      TSfree(data);

      break;
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

      TSfree(data);

      break;
    }

    data->key = TSCacheKeyCreate();
    if (TSCacheKeyDigestFromUrlSet(data->key, data->url_loc) != TS_SUCCESS) {
      TSCacheKeyDestroy(data->key);

      TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->url_loc);
      TSHandleMLocRelease(data->bufp, data->hdr_loc, data->location_loc);
      TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->hdr_loc);

      TSfree(data);

      break;
    }

    /* ... and RFC 6249 "Link: <...>; rel=duplicate" header */
    data->link_loc = TSMimeHdrFieldFind(data->bufp, data->hdr_loc, "Link", 4);
    while (data->link_loc) {

      count = TSMimeHdrFieldValuesCount(data->bufp, data->hdr_loc, data->link_loc);
      for (data->idx = 0; data->idx < count; data->idx += 1) {
        value = TSMimeHdrFieldValueStringGet(data->bufp, data->hdr_loc, data->link_loc, data->idx, &length);

        /* "string values returned from marshall buffers are not
         * null-terminated.  If you need a null-terminated value, then use
         * TSstrndup to automatically null-terminate a string",
         * http://trafficserver.apache.org/docs/trunk/sdk/http-headers/guide-to-trafficserver-http-header-system/index.en.html */
        value = TSstrndup(value, length);

        /* link-value = "<" URI-Reference ">" *( ";" link-param ) ; RFC 5988 */
        start = value + 1;

        end = strchr(start, '>');
        if (!end || !rel_duplicate(end + 1, value + length)) {
          continue;
        }

        contp = TSContCreate(location_handler, NULL);
        TSContDataSet(contp, data);
        TSCacheRead(contp, data->key);

        return 0;
      }

      next_loc = TSMimeHdrFieldNextDup(data->bufp, data->hdr_loc, data->link_loc);

      TSHandleMLocRelease(data->bufp, data->hdr_loc, data->link_loc);

      data->link_loc = next_loc;
    }

    TSCacheKeyDestroy(data->key);

    TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->url_loc);
    TSHandleMLocRelease(data->bufp, data->hdr_loc, data->location_loc);
    TSHandleMLocRelease(data->bufp, TS_NULL_MLOC, data->hdr_loc);

    TSfree(data);

    break;

  default:
    TSAssert(!"Unexpected event");
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);

  return 0;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSCont contp;
  TSPluginRegistrationInfo info;

  info.plugin_name = const_cast<char*>("metalink");
  info.vendor_name = const_cast<char*>("Jack Bates");
  info.support_email = const_cast<char*>("jack@nottheoilrig.com");

  if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
    TSError("Plugin registration failed");
  }

  contp = TSContCreate(handler, NULL);

  TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
  TSHttpHookAdd(TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
}
