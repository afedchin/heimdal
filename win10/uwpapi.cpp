
#include <windows.h>

#if defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_APP)
extern "C" 
{
  char *uwp_get_home_dir(void)
  {
    static char *home_dir = NULL;

    if (home_dir)
      return home_dir;

    auto localFolder = Windows::Storage::ApplicationData::Current->LocalFolder;
    int len = WideCharToMultiByte(CP_UTF8, 0, localFolder->Path->Data(), -1, NULL, 0, NULL, NULL);
    home_dir = (char *)malloc(len);
    if (home_dir) {
      WideCharToMultiByte(CP_UTF8, 0, localFolder->Path->Data(), -1, home_dir, len, NULL, NULL);
    }
    return home_dir;
  }
}
#endif
