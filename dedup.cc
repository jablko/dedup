#include <ts/ts.h>

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name = const_cast<char*>("dedup");
  info.vendor_name = const_cast<char*>("Jack Bates");
  info.support_email = const_cast<char*>("jack@nottheoilrig.com");

  if (!TSPluginRegister(TS_SDK_VERSION_3_0, &info)) {
    TSError("Plugin registration failed\n");
  }
}
