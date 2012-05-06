#include <stdio.h>
#include <ts/ts.h>

static int
dedup_plugin(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = (TSHttpTxn) edata;

  switch (event) {
  case TS_EVENT_HTTP_SEND_RESPONSE_HDR:

    TSMBuffer bufp;
    TSMLoc hdr_loc;
    TSMLoc location_loc;
    TSMLoc link_loc;
    TSMLoc next_loc;

    int idx;
    int count;

    const char *value;
    int length;

    if (TSHttpTxnClientRespGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
      TSError("Couldn't retrieve client request header\n");

      goto done;
    }

    location_loc = TSMimeHdrFieldFind(bufp, hdr_loc, TS_MIME_FIELD_LOCATION, TS_MIME_LEN_LOCATION);
    if (!location_loc) {
      TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);

      goto done;
    }

    link_loc = TSMimeHdrFieldFind(bufp, hdr_loc, "Link", 4);
    while (link_loc) {

      count = TSMimeHdrFieldValuesCount(bufp, hdr_loc, link_loc);
      for (idx = 0; idx < count; idx++) {
        value = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, link_loc, idx, &length);

        TSMimeHdrFieldValuesClear(bufp, hdr_loc, location_loc);
        TSMimeHdrFieldValueStringInsert(bufp, hdr_loc, location_loc, -1, value, length);
      }

      next_loc = TSMimeHdrFieldNextDup(bufp, hdr_loc, link_loc);

      TSHandleMLocRelease(bufp, hdr_loc, link_loc);

      link_loc = next_loc;
    }

    TSHandleMLocRelease(bufp, hdr_loc, location_loc);
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);

done:
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
