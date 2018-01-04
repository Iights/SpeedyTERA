#include "dllmain.h"

#include "hook.h"
#include "console.h"
#include "process.h"
#include "themida.h"
#include "network.h"
#include "plugin.h"
#include "engine.h"

char *TERA_EXE = "TERA.exe";

HMODULE hDLL;
LPVOID teraBase;
DWORD teraSize;

extern "C" __declspec (dllexport) void __cdecl dummy(HWND hWnd, HINSTANCE hInst, LPTSTR lpCmdLine, int nCmdShow) { }

void initAlone() {
  char szDLL[MAX_PATH];
  GetModuleFileName(hDLL, szDLL, MAX_PATH);

  if (injectDLL(TERA_EXE, szDLL) == FALSE) {
    MessageBox(0, "[!] TERA.exe not running or not enough privileges", "SpeedyTera ERROR", MB_ICONERROR | MB_OK);
  }
}

void handleConsole() {
  //printf("[Debug] handleConsole = 0x%04X\n", (DWORD)&handleConsole);
  char buf[MAX_PATH];
  while (true) {
    printf("> ");
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin) != NULL) {
      buf[strcspn(buf, "\r\n")] = '\0';
      if (!strlen(buf)) continue;
      if ((_stricmp(buf, "printdebug") == 0)) {
        //printf("GObjects: 0x%X\n", GObjects);
        //printf("GNames:   0x%X\n", GNames);
        InitCore();
      }
      else if ((_stricmp(buf, "quit") == 0) || (_stricmp(buf, "exit") == 0)) {
        unloadAll();
      }
      else {
        printf("Unknown command '%s'.\n", buf);
      }
    }
  }
}

void initHooked() {
  MODULEENTRY32 me = { 0 };
  getModule(GetCurrentProcessId(), TERA_EXE, me);
  teraBase = me.modBaseAddr;
  teraSize = me.modBaseSize;

  spawnConsole();
  printf("[+] SpeedyTera DEV\n");

  patchThemida();
  patchCrypto();
  loadPlugins();

  handleConsole();
}

void unloadAll() {
  unloadPlugins();
  restoreCrypto();
  restoreThemida();
  exitConsole();
  FreeLibraryAndExitThread(hDLL, 0);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved) {
  switch (ulReason) {
  case DLL_PROCESS_ATTACH: {
    DisableThreadLibraryCalls(hModule);
    hDLL = hModule;

    char szPath[MAX_PATH] = { 0 };
    GetModuleFileName(GetModuleHandle(0), szPath, MAX_PATH);
    char *szApp = strrchr(szPath, '\\') + 1;

    if (_stricmp(szApp, TERA_EXE) == 0) {
      CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)initHooked, NULL, NULL, NULL);
    }
    else {
      initAlone();
    }

    break;
  }
  case DLL_PROCESS_DETACH:
    if(hasConsole) exitConsole();
    break;
  }

  return TRUE;
}
