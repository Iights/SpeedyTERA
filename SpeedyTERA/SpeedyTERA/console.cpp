#include "dllmain.h"
#include "console.h"

BOOL hasConsole = FALSE;

BOOL CtrlHandler(DWORD fdwCtrlType)
{
  switch (fdwCtrlType) {
  case CTRL_C_EVENT:
  case CTRL_CLOSE_EVENT:
    unloadAll();
    return TRUE;
  default:
    return FALSE;
  }
}

BOOL spawnConsole() {
  if(!AllocConsole()) return FALSE;

  FILE* fp;
  freopen_s(&fp, "CONOUT$", "w", stdout);
  freopen_s(&fp, "CONOUT$", "w", stderr);
  freopen_s(&fp, "CONIN$", "r", stdin);

  SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);

  hasConsole = TRUE;
  return TRUE;
}

BOOL exitConsole() {
  fclose(stdin);
  fclose(stdout);
  fclose(stderr);
  hasConsole = FALSE;
  return FreeConsole();
}
