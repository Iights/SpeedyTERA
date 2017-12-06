/*
TERA.exe+15626B0 - 55                    - push ebp
TERA.exe+15626B1 - 8B EC                 - mov ebp,esp
TERA.exe+15626B3 - 83 EC 28              - sub esp,28 { 40 }
TERA.exe+15626B6 - 8B 41 04              - mov eax,[ecx+04]
TERA.exe+15626B9 - 8B 55 0C              - mov edx,[ebp+0C]
TERA.exe+15626BC - 53                    - push ebx
TERA.exe+15626BD - 56                    - push esi
TERA.exe+15626BE - 57                    - push edi
TERA.exe+15626BF - 8D 79 04              - lea edi,[ecx+04]
TERA.exe+15626C2 - 89 7D DC              - mov [ebp-24],edi
TERA.exe+15626C5 - 85 C0                 - test eax,eax
...

TERA.exe+1561030 - 55                    - push ebp
TERA.exe+1561031 - 8B EC                 - mov ebp,esp
TERA.exe+1561033 - 83 EC 28              - sub esp,28 { 40 }
TERA.exe+1561036 - 8B 41 04              - mov eax,[ecx+04]
TERA.exe+1561039 - 8B 55 0C              - mov edx,[ebp+0C]
TERA.exe+156103C - 53                    - push ebx
TERA.exe+156103D - 56                    - push esi
TERA.exe+156103E - 57                    - push edi
TERA.exe+156103F - 8D 79 04              - lea edi,[ecx+04]
TERA.exe+1561042 - 89 7D DC              - mov [ebp-24],edi
TERA.exe+1561045 - 85 C0                 - test eax,eax
...

01961AE4 - E8 C70B0000 - CALL 019626B0
01962A02 - E8 A9FCFFFF - CALL 019626B0

01961382 - E8 A9FCFFFF - CALL 01961030
01961BD1 - E8 5AF4FFFF - CALL 01961030

*/

#define ADDR_ENCRYPT_FN1 (DWORD)0x015626B0
#define ADDR_CALL_ENCRYPT_FN1_1 (DWORD)0x01561AE4
#define ADDR_CALL_ENCRYPT_FN1_2 (DWORD)0x01562A02

#define ADDR_ENCRYPT_FN2 (DWORD)0x01561030
#define ADDR_CALL_ENCRYPT_FN2_1 (DWORD)0x01561382
#define ADDR_CALL_ENCRYPT_FN2_2 (DWORD)0x01561BD1

#define ADDR_NET_BUFFER (DWORD)0x022CCE38
