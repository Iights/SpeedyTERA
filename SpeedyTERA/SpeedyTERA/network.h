#pragma once
typedef void(__cdecl * defHookCallback)(char *, size_t);

extern std::vector<defHookCallback> cbOnBeforeEncrypt;
extern std::vector<defHookCallback> cbOnAfterEncrypt;
extern std::vector<defHookCallback> cbOnBeforeDecrypt;
extern std::vector<defHookCallback> cbOnAfterDecrypt;

void patchCrypto(void *base, size_t size);
