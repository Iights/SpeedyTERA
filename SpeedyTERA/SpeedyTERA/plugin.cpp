#include "dllmain.h"
#include "plugin.h"

#include "network.h"

std::vector<HMODULE> hPlugins = {};

BOOL loadPlugins() {
  WIN32_FIND_DATA fd = { sizeof(fd) };

  char szPath[MAX_PATH] = { 0 };
  GetModuleFileNameA(hDLL, szPath, sizeof(szPath));
  char *pNull = strrchr(szPath, '\\') + 1; 
  pNull[0] = '\0';
  strcat_s(szPath, "..\\..\\PluginExample\\Debug\\");

  HANDLE hFind;
  char szPluginSearch[MAX_PATH] = { 0 };
  strcpy_s(szPluginSearch, szPath);
  strcat_s(szPluginSearch, "*.dll");

  if (hFind = FindFirstFile(szPluginSearch, &fd)) {
    do {
      char szDLL[MAX_PATH] = { 0 };
      strcpy_s(szDLL, szPath);
      strcat_s(szDLL, fd.cFileName);
      printf("[Plugin] * %s\n", fd.cFileName);

      HMODULE hLib = LoadLibrary(szDLL);
      if (hLib == NULL) continue;
      hPlugins.push_back(hLib);

      FARPROC lpHook;
      lpHook = GetProcAddress(hLib, "onBeforeEncrypt");
      if (lpHook != NULL) cbOnBeforeEncrypt.push_back((defHookCallback)lpHook);
      lpHook = GetProcAddress(hLib, "onAfterEncrypt");
      if (lpHook != NULL) cbOnAfterEncrypt.push_back((defHookCallback)lpHook);

      lpHook = GetProcAddress(hLib, "onBeforeDecrypt");
      if (lpHook != NULL) cbOnBeforeDecrypt.push_back((defHookCallback)lpHook);
      lpHook = GetProcAddress(hLib, "onAfterDecrypt");
      if (lpHook != NULL) cbOnAfterDecrypt.push_back((defHookCallback)lpHook);

    } while (FindNextFile(hFind, &fd));

    FindClose(hFind);
    return TRUE;
  }

  return FALSE;
}

BOOL unloadPlugins() {
  for (HMODULE hMod : hPlugins) {
    FreeLibrary(hMod);
  }
  return TRUE;
}
