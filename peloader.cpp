#include "peloader.h"

#ifdef spy_ExitProcess
typedef VOID (WINAPI *_ExitProcess)(__in UINT uExitCode);
_ExitProcess g_ExitProcess = NULL;
LPDWORD g_ImpExitProcess = NULL;
#endif

PELoader::PELoader(std::wstring str) : g_hLoadedModule(NULL)
{
    file = str;
}

void PELoader::MessageGetLastError( HWND hWndParent, LPCTSTR szTitle )
{
  LPTSTR lpMsgBuf;
  if ( FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL,
                      GetLastError(),
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      (LPTSTR) &lpMsgBuf,
                      0,
                      NULL ) )
  {
    // Display the string.
    MessageBox( hWndParent, (LPCTSTR)lpMsgBuf, szTitle, MB_OK + MB_ICONERROR );
    // Free the buffer.
    LocalFree( lpMsgBuf );
  }
};

HMODULE PELoader::PeLoadModule(LPBYTE lpbImage, LPDWORD lpdwError)
{
    if (lpdwError) *lpdwError = 0;
    if (IMAGE_IS_PE(lpbImage))
    {
        HMODULE lpbBase = (HMODULE) VirtualAlloc( NULL,
            //(LPVOID)IMAGE_GET_NTHEADER(lpbImage)->OptionalHeader.ImageBase,
            IMAGE_GET_NTHEADER(lpbImage)->OptionalHeader.SizeOfImage,
            MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        if (lpbBase)
        {
            // headers copy
            LPBYTE lpbHeaders = (LPBYTE) VirtualAlloc( lpbBase,
                IMAGE_GET_NTHEADER(lpbImage)->OptionalHeader.SizeOfHeaders,
                MEM_COMMIT, PAGE_EXECUTE_READWRITE );
            if(lpbHeaders)
            {
                CopyMemory( lpbHeaders, lpbImage, IMAGE_GET_NTHEADER(lpbImage)->OptionalHeader.SizeOfHeaders );
                // section loading
                // macro IMAGE_FIRST_SECTION defined in WinNT.h
                PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(IMAGE_GET_NTHEADER(lpbImage));
                for (DWORD i=0;i<IMAGE_GET_NTHEADER(lpbImage)->FileHeader.NumberOfSections;i++,pish++)
                {
                    if (pish->VirtualAddress)
                    {
                        LPBYTE lpbSectionBase = (LPBYTE) VirtualAlloc(
                            (LPVOID)((DWORD)lpbBase+pish->VirtualAddress),
                            pish->Misc.VirtualSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
                        if (lpbSectionBase)
                        {
                            ZeroMemory(lpbSectionBase,pish->Misc.VirtualSize);
                            // macro min defined in WinDef.h
                            CopyMemory(lpbSectionBase, lpbImage + pish->PointerToRawData,
                                min(pish->Misc.VirtualSize,pish->SizeOfRawData));
                        }
                        else if (lpdwError) *lpdwError = ERR_IMAGE_NOT_SVALLOC;
                    }
                }
                DWORD dwOldProtect = 0;
                VirtualProtect(lpbBase,
                    IMAGE_GET_NTHEADER(lpbImage)->OptionalHeader.SizeOfHeaders,
                    PAGE_EXECUTE_READWRITE, &dwOldProtect);

                return lpbBase;
            }
            else if (lpdwError) *lpdwError = ERR_IMAGE_NOT_HVALLOC;
        }
        else if (lpdwError) *lpdwError = ERR_IMAGE_NOT_VALLOC;
    }
    else if (lpdwError) *lpdwError = ERR_IMAGE_IS_NOT_PE;
    return 0;
}

DWORD PELoader::PeUnloadModule()
{
    PIMAGE_OPTIONAL_HEADER32 pOptionalHeader =
        &IMAGE_GET_NTHEADER(g_hLoadedModule)->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDirectoryImport =
        IMAGE_GET_DIRECTORY(g_hLoadedModule,IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (pDirectoryImport->VirtualAddress)
    {
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)g_hLoadedModule + pDirectoryImport->VirtualAddress);
        // loop for IMAGE_IMPORT_DESCRIPTOR[]
        while (pImportDescriptor->Name)
        {
            TCHAR szModuleName[MINCHAR] = __TEXT("");
            #ifdef UNICODE
            MultiByteToWideChar( CP_ACP, MB_PRECOMPOSED,
                (LPCSTR)((DWORD)g_hLoadedModule + pImportDescriptor->Name), -1,
                szModuleName, MINCHAR );
            #else
            lstrcpy(szModuleName,(LPCSTR)((DWORD)hModule + pImportDescriptor->Name));
            #endif
            HMODULE hImpModule = ::GetModuleHandle(szModuleName);
//            if (hImpModule) ::FreeLibrary(hImpModule);
            // Next
            pImportDescriptor++;
        }
    }
    PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(IMAGE_GET_NTHEADER(g_hLoadedModule));
    for (DWORD i=0;i<IMAGE_GET_NTHEADER(g_hLoadedModule)->FileHeader.NumberOfSections;i++,pish++)
    {
        if (pish->VirtualAddress)
        {
            VirtualFree((LPVOID)((DWORD)g_hLoadedModule+pish->VirtualAddress),
                0,MEM_DECOMMIT);
        }
    }
    VirtualFree( g_hLoadedModule,
        IMAGE_GET_NTHEADER(g_hLoadedModule)->OptionalHeader.SizeOfHeaders,
        MEM_DECOMMIT);
    VirtualFree( g_hLoadedModule, 0, MEM_RELEASE );
    return 0;
}

#ifdef spy_ExitProcess
// spy
void WINAPI PELoader::spyExitProcess(__in UINT uExitCode)
{
    DWORD dwOldProtection = 0;
    if (VirtualProtect((LPVOID)g_ImpExitProcess,sizeof(DWORD),
        PAGE_EXECUTE_READWRITE,&dwOldProtection))
    {
        *g_ImpExitProcess = (DWORD)g_ExitProcess;
        VirtualProtect((LPVOID)g_ImpExitProcess,sizeof(DWORD),
                dwOldProtection,&dwOldProtection);
    }
    PeUnloadModule();
    g_ExitProcess(uExitCode); // ПАДАЕТ ТУТ!!!
}
#endif

DWORD PELoader::PeProcessRelocations(HMODULE hModule,LONG lImageBaseDelta)
{
    PIMAGE_FIXUP_ENTRY pFixup;
    PIMAGE_DATA_DIRECTORY pDirectoryBaseReloc =
        IMAGE_GET_DIRECTORY(hModule,IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (pDirectoryBaseReloc->VirtualAddress)
    {
        PIMAGE_BASE_RELOCATION pRelocation =
            (PIMAGE_BASE_RELOCATION)((DWORD)hModule + pDirectoryBaseReloc->VirtualAddress);

        DWORD dwRelocsSize = pDirectoryBaseReloc->Size;

        while (dwRelocsSize > 0)
        {
            dwRelocsSize -= pRelocation->SizeOfBlock;
            // Process current relocation block
            for (pFixup = (PIMAGE_FIXUP_ENTRY)
                    (((LPBYTE) pRelocation) + IMAGE_SIZEOF_BASE_RELOCATION);
                (DWORD)pFixup < (DWORD)pRelocation + pRelocation->SizeOfBlock;
                pFixup++)
            {
                LPDWORD pFixupVA = NULL;
                DWORD t = 0;
                switch (pFixup->wType)
                {
                case IMAGE_REL_BASED_ABSOLUTE:
                    // no fixup required
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    // HighLow - (32-bits) relocate the high and low half
                    // of an address.
                    pFixupVA = (LPDWORD) ((DWORD)hModule + pRelocation->VirtualAddress +
                        pFixup->wOffset);

                    t = (DWORD)lImageBaseDelta;
                    *pFixupVA += t;

                    break;
                default:
                    return ERR_IMAGE_FIXUP_INVALID;
                }
            }
            pRelocation = (PIMAGE_BASE_RELOCATION)pFixup;
        }
    }
    else
        // Decided to load at different base, but no relocs present
        return ERR_IMAGE_NO_FIXUP;

    return 0;
}

DWORD PELoader::PeProcessImports(HMODULE hModule)
{
#ifdef spy_ExitProcess
    WORD wEP = 0;
#endif
    PIMAGE_OPTIONAL_HEADER32 pOptionalHeader =
        &IMAGE_GET_NTHEADER(hModule)->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDirectoryImport =
        IMAGE_GET_DIRECTORY(hModule,IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (pDirectoryImport->VirtualAddress)
    {
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hModule + pDirectoryImport->VirtualAddress);
        // loop for IMAGE_IMPORT_DESCRIPTOR[]
        while (pImportDescriptor->Name)
        {
            TCHAR szModuleName[MINCHAR] = __TEXT("");
            #ifdef UNICODE
            MultiByteToWideChar( CP_ACP, MB_PRECOMPOSED,
                (LPCSTR)((DWORD)hModule+pImportDescriptor->Name), -1,
                szModuleName, MINCHAR );
            #else
            lstrcpy(szModuleName,(LPCSTR)((DWORD)hModule+pImportDescriptor->Name));
            #endif
            HMODULE hImpModule = ::LoadLibrary(szModuleName);
            if (!hImpModule)
            {
                // + message for name of dll
                return ERR_IMAGE_IMPLIB_NOT_LOADED;
            }
#ifdef spy_ExitProcess
            if (lstrcmpi(szModuleName,__TEXT("KERNEL32.DLL"))==0) wEP = 1;
            else wEP = 0;
#endif
            // Thunk[]
            PIMAGE_THUNK_DATA pitd = (PIMAGE_THUNK_DATA)
            ((DWORD)hModule + (pImportDescriptor->OriginalFirstThunk ?
                pImportDescriptor->OriginalFirstThunk :
                pImportDescriptor->FirstThunk));
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)
                ((DWORD)hModule + pImportDescriptor->FirstThunk);

            // loop for IMAGE_THUNK_DATA
            while(pitd->u1.AddressOfData)
            {
                LPCSTR lpProcName = ((pitd->u1.Ordinal & IMAGE_ORDINAL_FLAG32) ?
                    (LPCSTR)(IMAGE_ORDINAL32(pitd->u1.Ordinal)) :
                    (LPCSTR)((PIMAGE_IMPORT_BY_NAME)((DWORD)hModule + pitd->u1.AddressOfData))->Name);
                DWORD dwFunc = (DWORD)GetProcAddress(hImpModule,lpProcName);
#ifdef spy_ExitProcess
                if (wEP)
                {
                    if (pitd->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                    {
                        if (IMAGE_ORDINAL32(pitd->u1.Ordinal)==183) wEP |= 0x0100;
                    }
                    else
                    {
                        TCHAR szProcName[MINCHAR] = __TEXT("");
                        #ifdef UNICODE
                        MultiByteToWideChar( CP_ACP, MB_PRECOMPOSED,
                            (LPCSTR)((PIMAGE_IMPORT_BY_NAME)((DWORD)hModule + pitd->u1.AddressOfData))->Name, -1,
                            szProcName, MINCHAR );
                        #else
                        lstrcpy(szProcName,(LPCSTR)((PIMAGE_IMPORT_BY_NAME)((DWORD)hModule + pitd->u1.AddressOfData))->Name);
                        #endif
                        if (lstrcmpi(szProcName,__TEXT("ExitProcess"))==0)  wEP |= 0x0100;
                    }
                    if (wEP&0x0100)
                    {
                        g_ExitProcess = (_ExitProcess)dwFunc;
                        dwFunc = (DWORD)spyExitProcess;
                        g_ImpExitProcess = &(pFirstThunk->u1.Function);
                        wEP = 0;
                    }
                }
#endif
                pFirstThunk->u1.Function = dwFunc;
                pFirstThunk++;
                pitd++;
            }
            // Next
            pImportDescriptor++;
        }
    }
    else return ERR_IMAGE_NO_IMPORT;
    return 0;
}

DWORD PELoader::PeGetSectionProtection(DWORD dwCharacteristics)
{
    DWORD dwProtection = 0;

    if (dwCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
        dwProtection |= PAGE_NOCACHE;

    if ((dwCharacteristics & IMAGE_SCN_MEM_EXECUTE) &&
        (dwCharacteristics & IMAGE_SCN_MEM_READ) &&
        (dwCharacteristics & IMAGE_SCN_MEM_WRITE))
        dwProtection |= PAGE_EXECUTE_READWRITE;
    else if ((dwCharacteristics & IMAGE_SCN_MEM_EXECUTE) &&
        (dwCharacteristics & IMAGE_SCN_MEM_READ))
        dwProtection |= PAGE_EXECUTE_READ;
    else if ((dwCharacteristics & IMAGE_SCN_MEM_READ) &&
        (dwCharacteristics & IMAGE_SCN_MEM_WRITE))
        dwProtection |= PAGE_READWRITE;
    else if (dwCharacteristics & IMAGE_SCN_MEM_WRITE)
        dwProtection |= PAGE_WRITECOPY;
    else if (dwCharacteristics & IMAGE_SCN_MEM_READ)
        dwProtection |= PAGE_READONLY;
    else
        dwProtection |= PAGE_EXECUTE_READWRITE;

    return dwProtection;
}

DWORD PELoader::PeSetSectionProtection(HMODULE hModule)
{
    DWORD dwReturn = 0;
    PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(IMAGE_GET_NTHEADER(hModule));
    for (DWORD i=0;i<IMAGE_GET_NTHEADER(hModule)->FileHeader.NumberOfSections;i++,pish++)
    {
        if (pish->VirtualAddress)
        {
            DWORD dwOldProtection = 0;
            if (!VirtualProtect((LPVOID)((DWORD)hModule + pish->VirtualAddress),pish->Misc.VirtualSize,
                PeGetSectionProtection(pish->Characteristics),&dwOldProtection))
                dwReturn = ERR_IMAGE_SEC_PROTECTION_FAILED;
        }
    }
    return dwReturn;
}

void PELoader::peExecute(HMODULE hModule)
{
    // PEB.ImageBaseAddress correction for resource functions
     //((TEB*)__readfsdword(PcTeb))->Peb->SectionBaseAddress = (PVOID)hModule;
    _mainCRTStartup newmain = (_mainCRTStartup)((DWORD)hModule + IMAGE_GET_NTHEADER(hModule)->OptionalHeader.AddressOfEntryPoint);
    newmain();
}

HMODULE PELoader::GetModuleDetail()
{
    if(file.empty())
    {
        return NULL;
    }

    if (::GetFileAttributes(file.c_str())!=INVALID_FILE_ATTRIBUTES)
    {
        HANDLE hFile = ::CreateFile( file.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL );
        if(hFile!=INVALID_HANDLE_VALUE) {
            DWORD dwFileSizeHigh = 0;
            DWORD dwImageSize = ::GetFileSize(hFile,&dwFileSizeHigh);
            if (dwFileSizeHigh==0)
            {
                HANDLE hMappedFile = ::CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
                ::CloseHandle(hFile);
                if(hMappedFile) {
                    LPVOID lpMappedFile = ::MapViewOfFile(hMappedFile,FILE_MAP_READ,0,0,0);
                    ::CloseHandle(hMappedFile);
                    if(lpMappedFile) {
                        DWORD dwError = 0;
                        g_hLoadedModule = PeLoadModule((LPBYTE)lpMappedFile,&dwError);
                        ::UnmapViewOfFile(lpMappedFile);
                        return g_hLoadedModule;
                    }
                    else { return NULL; }
                }
                else { return NULL; }
            }
            else { return NULL; }
        }
        else { return NULL; }
    }
    else { return NULL; }
}

void PELoader::CloseModule()
{
    if(g_hLoadedModule != NULL)
    {
        PeUnloadModule();
    }
}

void PELoader::LoadExe(LPCTSTR szFileName)
{
    if (::GetFileAttributes(szFileName)!=INVALID_FILE_ATTRIBUTES)
    {
        HANDLE hFile = ::CreateFile( szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL );
        if(hFile!=INVALID_HANDLE_VALUE) {
            DWORD dwFileSizeHigh = 0;
            DWORD dwImageSize = ::GetFileSize(hFile,&dwFileSizeHigh);
            if (dwFileSizeHigh==0)
            {
                HANDLE hMappedFile = ::CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
                ::CloseHandle(hFile);
                if(hMappedFile) {
                    LPVOID lpMappedFile = ::MapViewOfFile(hMappedFile,FILE_MAP_READ,0,0,0);
                    ::CloseHandle(hMappedFile);
                    if(lpMappedFile) {
                        DWORD dwError = 0;
                        g_hLoadedModule = PeLoadModule((LPBYTE)lpMappedFile,&dwError);
                        ::UnmapViewOfFile(lpMappedFile);
                        if (g_hLoadedModule)
                        {
                            if (dwError)
                                ::MessageBox(::GetDesktopWindow(),__TEXT("File loaded unsuccessful"),__TEXT("Peloader"),MB_OK+MB_ICONERROR);
//                                print_f(_TEXT("file loaded unsuccessful: %u\n"),dwError);
                            else
                            {
                                LONG lImageBaseDelta = (LONG)((DWORD)g_hLoadedModule - IMAGE_GET_NTHEADER(g_hLoadedModule)->OptionalHeader.ImageBase);
                                if (lImageBaseDelta)
                                {
                                    // Processing relocs
                                    dwError = PeProcessRelocations(g_hLoadedModule,lImageBaseDelta);
//                                    if (dwError) print_f(_TEXT("can't processed relocations: %u\n"),dwError);
                                }
//                                else print_f(_TEXT("relocations not processed\n"));
                                // Processing import
                                dwError = PeProcessImports(g_hLoadedModule);
//                                if (dwError) print_f(_TEXT("can't process import : %u\n"),dwError);
                                // Set protection
                                //dwError = PeSetSectionProtection(g_hLoadedModule);
//                                if (dwError) print_f(_TEXT("can't section protect : %u\n"),dwError);
                                peExecute(g_hLoadedModule);

                                //dwError = PeUnloadModule();
                                //if (dwError) print_f(_TEXT("can't unload pe image: %u\n"),dwError);

                            }
                        }
//                        else print_f(_TEXT("can't load pe image: %08X\n"),dwError);
                    }
                    else MessageGetLastError(::GetDesktopWindow(),__TEXT("Can't mapview file"));
                }
                else MessageGetLastError(::GetDesktopWindow(),__TEXT("Can't mapping file"));
            }
            else
            {
                ::MessageBox(::GetDesktopWindow(),__TEXT("File is very large"),__TEXT("Peloader"),MB_OK+MB_ICONERROR);
                ::CloseHandle(hFile);
            }
        }
        else MessageGetLastError(::GetDesktopWindow(),__TEXT("Can't open file"));
    }
    else MessageGetLastError(::GetDesktopWindow(),__TEXT("Can't find file"));
}

void * __cdecl memset (
        void *dst,
        int val,
        size_t count
        )
{
        void *start = dst;

        while (count--) {
                *(char *)dst = (char)val;
                dst = (char *)dst + 1;
        }

        return(start);
}

void * __cdecl memcpy (
        void * dst,
        const void * src,
        size_t count
        )
{
        void * ret = dst;

        while (count--) {
                *(char *)dst = *(char *)src;
                dst = (char *)dst + 1;
                src = (char *)src + 1;
        }

        return(ret);
}
