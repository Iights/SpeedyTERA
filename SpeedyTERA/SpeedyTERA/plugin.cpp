#include "dllmain.h"
#include "plugin.h"

#include "network.h"

char * PLUGIN_PATH = "C:\\Users\\Administrador\\source\\repos\\SpeedyTERA\\PluginExample\\Debug\\";

BOOL loadPlugins() {
  WIN32_FIND_DATA fd = { sizeof(fd) };

  HANDLE hFind;
  char szPluginSearch[MAX_PATH] = { 0 };
  strcpy_s(szPluginSearch, PLUGIN_PATH);
  strcat_s(szPluginSearch, "*.dll");

  if (hFind = FindFirstFile(szPluginSearch, &fd)) {

    do {
      char szDLL[MAX_PATH] = { 0 };
      strcpy_s(szDLL, PLUGIN_PATH);
      strcat_s(szDLL, fd.cFileName);

      HMODULE hLib = LoadLibrary(szDLL);
      if (hLib == NULL) continue;

      FARPROC lpHook;
      lpHook = GetProcAddress(hLib, "onBeforeEncrypt");
      if (lpHook != NULL) cbOnBeforeEncrypt.push_back((defHookCallback)lpHook);
      lpHook = GetProcAddress(hLib, "onAfterEncrypt");
      if (lpHook != NULL) cbOnAfterEncrypt.push_back((defHookCallback)lpHook);

      lpHook = GetProcAddress(hLib, "onBeforeDecrypt");
      if (lpHook != NULL) cbOnBeforeDecrypt.push_back((defHookCallback)lpHook);
      lpHook = GetProcAddress(hLib, "onAfterDecrypt");
      if (lpHook != NULL) cbOnAfterDecrypt.push_back((defHookCallback)lpHook);

      printf("[Plugin] Loaded: %s\n", szDLL);

    } while (FindNextFile(hFind, &fd));

    FindClose(hFind);
    return TRUE;
  }

  return FALSE;
}
