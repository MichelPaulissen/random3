#ifdef __cplusplus
extern "C" {
#endif

#ifndef RANDOM3_H
#define RANDOM3_H

#ifdef WIN32
#define R3_WINDOWS
#endif

#ifdef R3_WINDOWS
#pragma comment(lib, "advapi32.lib")

    #define HCRYPTPROV unsigned long long
    #define BOOL int
    #define LPCWSTR const wchar_t*
    #define DWORD unsigned long
    #define BYTE unsigned char
    #define WINADVAPI
    #define WINAPI __stdcall

    #define PROV_RSA_FULL           1
    #define CRYPT_VERIFYCONTEXT     0xF0000000
    #define CRYPT_SILENT            0x00000040

    WINADVAPI BOOL WINAPI CryptAcquireContextW(
        HCRYPTPROV *phProv,
        LPCWSTR pszContainer,
        LPCWSTR pszProvider,
        DWORD dwProvType,
        DWORD dwFlags
    );
    WINADVAPI BOOL WINAPI CryptGenRandom(
        _In_                    HCRYPTPROV  hProv,
        _In_                    DWORD   dwLen,
        _Inout_updates_bytes_(dwLen)   BYTE    *pbBuffer
    );
    WINADVAPI BOOL WINAPI CryptReleaseContext(
        _In_    HCRYPTPROV  hProv,
        _In_    DWORD       dwFlags
    );
#else
#ifndef R3_NO_STDIO
#include <stdio.h>
#endif
#endif

typedef struct
{
#ifdef R3_WINDOWS
    HCRYPTPROV prov;
#else
    FILE* urandom;
#endif
} r3_ctx;

r3_ctx r3_create_ctx();
void r3_destroy_ctx(r3_ctx ctx);
void r3_random(r3_ctx ctx, void* target, int bytes);

#endif // RANDOM3_H

#ifdef R3_IMPLEMENTATION

r3_ctx r3_create_ctx()
{
    r3_ctx ctx;
#ifdef R3_WINDOWS
    CryptAcquireContextW(&ctx.prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
#else
    ctx.urandom = fopen("/dev/urandom", "r");
#endif
    return ctx;
}

void r3_destroy_ctx(r3_ctx ctx)
{
#ifdef R3_WINDOWS
    CryptReleaseContext(ctx.prov, 0);
#else
    fclose(ctx.urandom);
#endif
}

void r3_random(r3_ctx ctx, void* target, int bytes)
{
#ifdef R3_WINDOWS
    CryptGenRandom(ctx.prov, bytes, target);
#else
    fread(target, 1, bytes, ctx.urandom);
#endif
}

#endif

#ifdef __cplusplus
} // extern "C"
#endif
