#pragma once
DWORD getPID(char *szName);
BOOL getModule(DWORD dwPID, char *szName, MODULEENTRY32 &module);
BOOL injectDLL(char *szProcess, char *szDLL);

