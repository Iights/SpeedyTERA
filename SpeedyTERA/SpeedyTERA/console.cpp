#include "dllmain.h"
#include "console.h"

BOOL hasConsole = FALSE;
FILE* fp;

BOOL spawnConsole() {
  if(!AllocConsole()) return FALSE;
  freopen_s(&fp, "CONIN$", "r", stdin);
  freopen_s(&fp, "CONOUT$", "w", stdout);
  freopen_s(&fp, "CONERR$", "w", stderr);
  hasConsole = TRUE;
  return TRUE;
}

BOOL exitConsole() {
  fclose(fp);
  hasConsole = FALSE;
  return FreeConsole();
}
