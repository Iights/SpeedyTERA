#include "dllmain.h"

#include "console.h"
#include "process.h"
#include "themida.h"
#include "network.h"
#include "plugin.h"

char *TERA_EXE = "TERA.exe";

extern "C" __declspec (dllexport) void __cdecl dummy(HWND hWnd, HINSTANCE hInst, LPTSTR lpCmdLine, int nCmdShow) { }

void initAlone(HMODULE hDLL) {
  char szDLL[MAX_PATH];
  GetModuleFileName(hDLL, szDLL, MAX_PATH);

  if (injectDLL(TERA_EXE, szDLL) == FALSE) {
    MessageBox(0, "[!] TERA.exe not running or not enough privileges", "SpeedyTera ERROR", MB_ICONERROR | MB_OK);
  }
}

void initHooked(HMODULE hDLL) {
  DWORD pID = getPID(TERA_EXE); 

  MODULEENTRY32 me;
  getModule(pID, TERA_EXE, me);

  LPVOID TeraBase = me.modBaseAddr;
  DWORD TeraSize = me.modBaseSize;

  spawnConsole();
  printf("[+] SpeedyTera v1.0\n");

  patchThemida(TeraBase, TeraSize);
  patchCrypto(TeraBase, TeraSize);

  loadPlugins();
  
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved) {
  switch (ulReason) {
  case DLL_PROCESS_ATTACH: {
    DisableThreadLibraryCalls(hModule);

    char szPath[MAX_PATH];
    GetModuleFileName(GetModuleHandle(0), szPath, MAX_PATH);
    char *szApp = strrchr(szPath, '\\') + 1;

    if (_stricmp(szApp, TERA_EXE) == 0) {
      initHooked(hModule);
    }
    else {
      initAlone(hModule);
    }

    break;
  }
  case DLL_PROCESS_DETACH:
    if(hasConsole) exitConsole();
    break;
  }

  return TRUE;
}
