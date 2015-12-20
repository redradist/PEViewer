#ifndef PELOADER_H
#define PELOADER_H

// Modify the following defines if you have to target a platform prior to the ones specified below.
// Refer to MSDN for the latest info on corresponding values for different platforms.
#ifndef WINVER                          // Specifies that the minimum required platform is Windows Vista.
#define WINVER 0x0600           // Change this to the appropriate value to target other versions of Windows.
#endif

#ifndef _WIN32_WINNT            // Specifies that the minimum required platform is Windows Vista.
#define _WIN32_WINNT 0x0600     // Change this to the appropriate value to target other versions of Windows.
#endif

#ifndef _WIN32_WINDOWS          // Specifies that the minimum required platform is Windows 98.
#define _WIN32_WINDOWS 0x0410 // Change this to the appropriate value to target Windows Me or later.
#endif

#ifndef _WIN32_IE                       // Specifies that the minimum required platform is Internet Explorer 7.0.
#define _WIN32_IE 0x0700        // Change this to the appropriate value to target other versions of IE.
#endif

#include <windows.h>
#include <cstdio>
#include <tchar.h>
#include <string>

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

#define SEH
//#define spy_ExitProcess

#define ERR_IMAGE_IS_NOT_PE              1
#define ERR_IMAGE_NOT_VALLOC             2
#define ERR_IMAGE_NOT_HVALLOC            3
#define ERR_IMAGE_NOT_SVALLOC            4
#define ERR_IMAGE_NO_FIXUP               5
#define ERR_IMAGE_FIXUP_INVALID          6
#define ERR_IMAGE_SEC_PROTECTION_FAILED  7
#define ERR_IMAGE_NO_IMPORT              8
#define ERR_IMAGE_IMPLIB_NOT_LOADED      9

#define LDRP_RELOCATION_INCREMENT        0x1
#define LDRP_RELOCATION_FINAL            0x2

#define IMAGE_GET_DOSHEADER( lpbImage ) ((PIMAGE_DOS_HEADER)lpbImage)
#define IMAGE_GET_NTHEADER( lpbImage ) ((PIMAGE_NT_HEADERS32)((DWORD)lpbImage + IMAGE_GET_DOSHEADER(lpbImage)->e_lfanew))
#define IMAGE_IS_PE( lpbImage ) (IMAGE_GET_DOSHEADER(lpbImage)->e_magic == IMAGE_DOS_SIGNATURE ? \
    (IMAGE_GET_NTHEADER(lpbImage)->Signature == IMAGE_NT_SIGNATURE ? TRUE : FALSE) : FALSE)
#define IMAGE_GET_DIRECTORY( lpbImage, DIRECTORY_ID ) \
    (&IMAGE_GET_NTHEADER(lpbImage)->OptionalHeader.DataDirectory[DIRECTORY_ID])

#ifdef spy_ExitProcess
typedef VOID (WINAPI *_ExitProcess)(__in UINT uExitCode);
extern _ExitProcess g_ExitProcess;
extern LPDWORD g_ImpExitProcess;
#endif

typedef struct
{
    WORD    wOffset:12;
    WORD    wType:4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;

// Process Envorinment Block
typedef struct _PEB {
    DWORD smth[2]; // doesn't matter
    PVOID SectionBaseAddress;
} PEB, *PPEB;

// Thread Environment Block
typedef struct _TEB {
    DWORD smth[12]; // doesn't matter
    PPEB Peb;
} TEB, *PTEB;

typedef void (__cdecl *_mainCRTStartup)(void);

#ifdef _MSC_VER
#pragma function(memset)
#pragma function(memcpy)
#endif

extern void * __cdecl memset (void *dst, int val, size_t count);
extern void * __cdecl memcpy (void * dst, const void * src, size_t count);

class PELoader
{
    HMODULE g_hLoadedModule;
    PELoader(PELoader const & );
    std::wstring file;
public:
    PELoader() : g_hLoadedModule(NULL) { }
    PELoader(std::wstring str);
    PELoader& operator =(wchar_t *str) {
        CloseModule();
        file = str;
        return *this;
    }

    std::wstring getFile() const {
        return file;
    }

    HMODULE GetModuleDetail();
    void CloseModule();
    void LoadExe(LPCTSTR szFileName);

private:
    void MessageGetLastError( HWND hWndParent, LPCTSTR szTitle );
    HMODULE PeLoadModule(LPBYTE lpbImage, LPDWORD lpdwError);
    DWORD PeUnloadModule();
#ifdef spy_ExitProcess
    // spy
    void WINAPI spyExitProcess(__in UINT uExitCode);
#endif
    DWORD PeProcessRelocations(HMODULE hModule,LONG lImageBaseDelta);
    DWORD PeProcessImports(HMODULE hModule);
    DWORD PeGetSectionProtection(DWORD dwCharacteristics);
    DWORD PeSetSectionProtection(HMODULE hModule);
    void peExecute(HMODULE hModule);
};

#endif // PELOADER_H
