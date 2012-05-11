#include <stdio.h>
#include <ts/ts.h>

typedef struct {

  TSHttpTxn txnp;
  TSMBuffer bufp;
  TSMLoc hdr_loc;
  TSMLoc location_loc;

} Info;

static int
handler(TSCont contp, TSEvent event, void *edata)
{
  Info *info = (Info*) TSContDataGet(contp);

  switch (event) {
  case TS_EVENT_CACHE_OPEN_READ:

    TSHandleMLocRelease(info->bufp, info->hdr_loc, info->location_loc);
    TSHandleMLocRelease(info->bufp, TS_NULL_MLOC, info->hdr_loc);

    TSHttpTxnReenable(info->txnp, TS_EVENT_HTTP_CONTINUE);

    TSfree(info);
    TSContDestroy(contp);

    break;

  case TS_EVENT_CACHE_OPEN_READ_FAILED:

    TSMimeHdrFieldValuesClear(info->bufp, info->hdr_loc, info->location_loc);
    TSMimeHdrFieldValueStringInsert(info->bufp, info->hdr_loc, info->location_loc, -1, "http://example.com/", 19);

    TSHandleMLocRelease(info->bufp, info->hdr_loc, info->location_loc);
    TSHandleMLocRelease(info->bufp, TS_NULL_MLOC, info->hdr_loc);

    TSHttpTxnReenable(info->txnp, TS_EVENT_HTTP_CONTINUE);

    TSfree(info);
    TSContDestroy(contp);

    break;

  default:
    TSAssert(!"Unexpected event");
  }

  return 0;
}

static int
dedup_plugin(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = (TSHttpTxn) edata;

  switch (event) {
  case TS_EVENT_HTTP_SEND_RESPONSE_HDR:

    TSMBuffer bufp;
    TSMLoc hdr_loc;
    TSMLoc location_loc;

    const char *value;
    int length;

    TSMLoc url_loc;
    TSCacheKey key;

    TSMLoc link_loc;
    TSMLoc next_loc;

    int idx;
    int count;

    if (TSHttpTxnClientRespGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
      TSError("Couldn't retrieve client request header\n");

      TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);

      break;
    }

    /* Assumption: Want to minimize cache read, so check first that:
     *
     *   1. response has "Location: ..." header
     *   2. response has RFC 6249 "Link: <...>; rel=duplicate" header
     *
     * Then scan if URL already exist in cache */

    /* If response has "Location: ..." header */
    location_loc = TSMimeHdrFieldFind(bufp, hdr_loc, TS_MIME_FIELD_LOCATION, TS_MIME_LEN_LOCATION);
    if (!location_loc) {
      TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);

      TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);

      break;
    }

    value = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, location_loc, 0, &length);

    /* If can't parse or lookup "Location: ..." URL, should still check if
     * response has RFC 6249 "Link: <...>; rel=duplicate" header? No: Can't
     * parse or lookup URL in "Location: ..." header is error */
    TSUrlCreate(bufp, &url_loc);
    if (TSUrlParse(bufp, url_loc, &value, value + length) != TS_PARSE_DONE) {

      TSHandleMLocRelease(bufp, TS_NULL_MLOC, url_loc);
      TSHandleMLocRelease(bufp, hdr_loc, location_loc);
      TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);

      TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);

      break;
    }

    key = TSCacheKeyCreate();
    if (TSCacheKeyDigestFromUrlSet(key, url_loc) != TS_SUCCESS) {
      TSCacheKeyDestroy(key);

      TSHandleMLocRelease(bufp, TS_NULL_MLOC, url_loc);
      TSHandleMLocRelease(bufp, hdr_loc, location_loc);
      TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);

      TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);

      break;
    }

    /* ... and RFC 6249 "Link: <...>; rel=duplicate" header */
    link_loc = TSMimeHdrFieldFind(bufp, hdr_loc, "Link", 4);
    while (link_loc) {

      count = TSMimeHdrFieldValuesCount(bufp, hdr_loc, link_loc);
      for (idx = 0; idx < count; idx++) {
        value = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, link_loc, idx, &length);

        contp = TSContCreate(handler, NULL);

        Info *info = (Info*) TSmalloc(sizeof(Info));
        info->txnp = txnp;
        info->bufp = bufp;
        info->hdr_loc = hdr_loc;
        info->location_loc = location_loc;

        TSContDataSet(contp, info);

        TSCacheRead(contp, key);

        TSCacheKeyDestroy(key);

        TSHandleMLocRelease(bufp, hdr_loc, link_loc);
        TSHandleMLocRelease(bufp, TS_NULL_MLOC, url_loc);

        return 0;
      }

      next_loc = TSMimeHdrFieldNextDup(bufp, hdr_loc, link_loc);

      TSHandleMLocRelease(bufp, hdr_loc, link_loc);

      link_loc = next_loc;
    }

    TSCacheKeyDestroy(key);

    TSHandleMLocRelease(bufp, TS_NULL_MLOC, url_loc);
    TSHandleMLocRelease(bufp, hdr_loc, location_loc);
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);

    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);

    break;

  default:
    TSAssert(!"Unexpected event");
  }

  return 0;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSCont contp;
  TSPluginRegistrationInfo info;

  info.plugin_name = const_cast<char*>("dedup");
  info.vendor_name = const_cast<char*>("Jack Bates");
  info.support_email = const_cast<char*>("jack@nottheoilrig.com");

  if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
    TSError("Plugin registration failed\n");
  }

  contp = TSContCreate(dedup_plugin, NULL);
  TSHttpHookAdd(TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
}
