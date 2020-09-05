#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include "data.h"
#include <stdio.h>
//#include <metahost.h>
//#pragma comment(lib, "mscoree.lib")
//
//#import "mscorlib.tlb" raw_interfaces_only auto_rename				\
//    high_property_prefixes("_get","_put","_putref")		\
//    rename("ReportEvent", "InteropServices_ReportEvent")
//using namespace mscorlib;
//
//typedef void*(*f_dummy)(void* rcx, void* rdx, void* r8, void* r9);

typedef HRESULT(__stdcall* f_CLRCreateInstance)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);
struct ddd {
    GUID CLSID_CLRMetaHost_l;// = { 0x9280188d,0xe8e,0x4867,{0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde} };
    GUID IID_ICLRMetaHost_l;// = { 0xD332DB9E,0xB9B3,0x4125,{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16} };
    GUID IID_ICLRRuntimeInfo_l;// = { 0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91} };
    GUID CLSID_CorRuntimeHost_l;// = { 0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };
    GUID IID_ICorRuntimeHost_l;// = { 0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };
    GUID IID_AppDomain_l;// = { 0x05f696dc, 0x2b29, 0x3663, {0xad, 0x8b, 0xc4, 0x38, 0x9c, 0xf2, 0xa7, 0x13} };
    wchar_t ver[20];// = L"v4.0.30319"
    wchar_t cla[64];// = L"Hack.Evil"
    wchar_t fun[64];// = L"Main"
    void* data;
    ULONG data_len;
    f_CLRCreateInstance CLRCreateInstance;
};

//__declspec(noinline) void inject(ddd* d) {//__stdcall
//    void* pMetaHost = NULL;
//    void* pRuntimeInfo = NULL;
//    void* pCorRuntimeHost = NULL;
//    void* spAppDomainThunk = NULL;
//    void* spDefaultAppDomain = NULL;
//    void* spAssembly = NULL;
//    void* spType = NULL;
//
//
//    d->CLRCreateInstance(d->CLSID_CLRMetaHost_l, d->IID_ICLRMetaHost_l, &pMetaHost);
//    reinterpret_cast<ICLRMetaHost*>(pMetaHost)->GetRuntime(d->ver, d->IID_ICLRRuntimeInfo_l, &pRuntimeInfo);
//    reinterpret_cast<ICLRRuntimeInfo*>(pRuntimeInfo)->GetInterface(d->CLSID_CorRuntimeHost_l, d->IID_ICorRuntimeHost_l, &pCorRuntimeHost);
//    reinterpret_cast<ICorRuntimeHost*>(pCorRuntimeHost)->Start();
//    reinterpret_cast<ICorRuntimeHost*>(pCorRuntimeHost)->GetDefaultDomain(reinterpret_cast<IUnknown**>(&spAppDomainThunk));
//    reinterpret_cast<IUnknown*>(spAppDomainThunk)->QueryInterface(d->IID_AppDomain_l, &spDefaultAppDomain);
//    SAFEARRAY arr;
//    arr.cbElements = 1;
//    arr.cDims = 1;
//    arr.fFeatures = 0;
//    arr.cLocks = 0;
//    arr.pvData = d->data;
//    arr.rgsabound->cElements = d->data_len;
//    arr.rgsabound->lLbound = 0;
//    reinterpret_cast<_AppDomain*>(spDefaultAppDomain)->Load_3(&arr, reinterpret_cast<_Assembly**>(&spAssembly));
//    reinterpret_cast<_Assembly*>(spAssembly)->GetType_2(reinterpret_cast<BSTR>(reinterpret_cast<BYTE*>(d->cla) + 4), reinterpret_cast<_Type**>(&spType));
//    VARIANTARG vtEmpty{ 0 };
//    VARIANTARG vtLengthRet{ 0 };
//    reinterpret_cast<_Type*>(spType)->InvokeMember_3(reinterpret_cast<BSTR>(reinterpret_cast<BYTE*>(d->fun) + 4),
//        static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public), NULL, vtEmpty, nullptr, &vtLengthRet);
//}

typedef LPVOID(__stdcall* f_VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
__declspec(noinline) void alloc(f_VirtualAlloc f){
    f(reinterpret_cast<LPVOID>(0), 10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

unsigned char shellcode[] =
{
    0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, //mov rax, orig_func            ///ofs 2  dec
    0x49, 0xBA, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, //mov r10, orig_hook_place      ///ofs 12 dec
    0x41, 0x52, //push   r10
    0x50, //push   rax
    0x53, //push   rbx
    0x51, //push   rcx
    0x52, //push   rdx
    0x41, 0x50, //push   r8
    0x41, 0x51, //push   r9
    0x55, //push   rbp
    0x57, //push   rdi

    0x48, 0x83, 0xEC, 0x38, //sub rsp, 0x38
    0x48, 0xB9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, //mov rcx, data_array           ///ofs 38 dec

    //shellcode: void inject(bbb*)
    0x40, 0x55, 0x53, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xB9, 0x48, 0x81, 0xEC,
    0xD0, 0x00, 0x00, 0x00, 0x33, 0xFF, 0x48, 0x8D, 0x51, 0x10, 0x4C, 0x8D,
    0x45, 0x6F, 0x48, 0x89, 0x7D, 0x6F, 0x48, 0x89, 0x7D, 0x77, 0x48, 0x8B,
    0xD9, 0x48, 0x89, 0x7D, 0x67, 0x48, 0x89, 0x7D, 0x7F, 0x48, 0x89, 0x7D,
    0xB7, 0x48, 0x89, 0x7D, 0xBF, 0x48, 0x89, 0x7D, 0xC7, 0xFF, 0x91, 0x98,
    0x01, 0x00, 0x00, 0x48, 0x8B, 0x4D, 0x6F, 0x4C, 0x8D, 0x43, 0x20, 0x48,
    0x8D, 0x53, 0x60, 0x4C, 0x8D, 0x4D, 0x77, 0x48, 0x8B, 0x01, 0xFF, 0x50,
    0x18, 0x48, 0x8B, 0x4D, 0x77, 0x4C, 0x8D, 0x43, 0x40, 0x48, 0x8D, 0x53,
    0x30, 0x4C, 0x8D, 0x4D, 0x67, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48, 0x48,
    0x8B, 0x4D, 0x67, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x50, 0x48, 0x8B, 0x4D,
    0x67, 0x48, 0x8D, 0x55, 0x7F, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x68, 0x48,
    0x8B, 0x4D, 0x7F, 0x48, 0x8D, 0x53, 0x50, 0x4C, 0x8D, 0x45, 0xB7, 0x48,
    0x8B, 0x01, 0xFF, 0x10, 0x48, 0x8B, 0x83, 0x88, 0x01, 0x00, 0x00, 0x4C,
    0x8D, 0x45, 0xBF, 0x48, 0x8B, 0x4D, 0xB7, 0x48, 0x8D, 0x55, 0xCF, 0x48,
    0x89, 0x45, 0xDF, 0x8B, 0x83, 0x90, 0x01, 0x00, 0x00, 0x89, 0x45, 0xE7,
    0x48, 0xC7, 0x45, 0xD3, 0x01, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xCF, 0x01,
    0x00, 0x00, 0x00, 0x89, 0x7D, 0xEB, 0x48, 0x8B, 0x01, 0xFF, 0x90, 0x68,
    0x01, 0x00, 0x00, 0x48, 0x8B, 0x4D, 0xBF, 0x48, 0x8D, 0x93, 0x8C, 0x00,
    0x00, 0x00, 0x4C, 0x8D, 0x45, 0xC7, 0x48, 0x8B, 0x01, 0xFF, 0x90, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x8B, 0x4D, 0xC7, 0x4C, 0x8D, 0x45, 0xEF, 0x4C,
    0x89, 0x44, 0x24, 0x30, 0x48, 0x8D, 0x93, 0x0C, 0x01, 0x00, 0x00, 0x33,
    0xC0, 0x48, 0x89, 0x7C, 0x24, 0x28, 0x0F, 0x57, 0xC0, 0x48, 0x89, 0x45,
    0x37, 0x0F, 0x11, 0x45, 0xEF, 0x4C, 0x8D, 0x45, 0x07, 0x48, 0x89, 0x45,
    0xFF, 0xF2, 0x0F, 0x10, 0x45, 0x37, 0x0F, 0x57, 0xC9, 0x48, 0x8B, 0x01,
    0x45, 0x33, 0xC9, 0x4C, 0x89, 0x44, 0x24, 0x20, 0x41, 0xB8, 0x18, 0x01,
    0x00, 0x00, 0x0F, 0x29, 0x4D, 0x07, 0xF2, 0x0F, 0x11, 0x45, 0x17, 0xFF,
    0x90, 0xC8, 0x01, 0x00, 0x00, 0x48, 0x81, 0xC4, 0xD0, 0x00, 0x00, 0x00,
    0x5F, 0x5B, 0x5D, 
    
    0x48, 0x83, 0xC4, 0x38, //add rsp, 0x38

    0x5F, //pop    rdi
    0x5D, //pop    rbp
    0x41, 0x59, //pop    r9
    0x41, 0x58, //pop    r8
    0x5A, //pop    rdx
    0x59, //pop    rcx
    0x5B, //pop    rbx
    0x58, //pop    rax
    0x41, 0x5A, //pop    r10

    0x49, 0x89, 0x02, //mov    QWORD PTR [r10],rax
    0x41, 0xFF, 0x22, //jmp    QWORD PTR [r10]
};

ddd dd{ 0 };

void orig(int xd) {
    _tprintf(TEXT("orig: %d!\n"), xd);
}

int main() {
    alloc(VirtualAlloc);
    return 0;
    ddd* d = &dd;

    d->CLSID_CLRMetaHost_l = { 0x9280188d,0xe8e,0x4867,{0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde} };
    d->IID_ICLRMetaHost_l = { 0xD332DB9E,0xB9B3,0x4125,{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16} };
    d->IID_ICLRRuntimeInfo_l = { 0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91} };
    d->CLSID_CorRuntimeHost_l = { 0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };
    d->IID_ICorRuntimeHost_l = { 0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };
    d->IID_AppDomain_l = { 0x05f696dc, 0x2b29, 0x3663, {0xad, 0x8b, 0xc4, 0x38, 0x9c, 0xf2, 0xa7, 0x13} };
    const wchar_t ver[] = L"v4.0.30319";
    memcpy_s(d->ver, sizeof(d->ver), ver, sizeof(ver));
    const wchar_t cla[] = L"Hack.Evil";
    memcpy_s((reinterpret_cast<BYTE*>(&d->cla) + 4), sizeof(d->cla) - 4, cla, sizeof(cla));
    *reinterpret_cast<DWORD*>(&d->cla) = sizeof(cla) - 2;
    const wchar_t fun[] = L"Main";
    memcpy_s((reinterpret_cast<BYTE*>(&d->fun) + 4), sizeof(d->fun) - 4, fun, sizeof(fun));
    *reinterpret_cast<DWORD*>(&d->fun) = sizeof(fun) - 2;
    //d.data = rawData;
    d->data_len = sizeof(rawData);
    HMODULE hMod = LoadLibrary(TEXT("mscoree.dll"));
    if (!hMod) return 1;
    d->CLRCreateInstance = (f_CLRCreateInstance)GetProcAddress(hMod, "CLRCreateInstance");

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (_tcscmp(entry.szExeFile, TEXT("sectorsedge.exe")) == 0)
            {
                _tprintf(TEXT("process found as %d!\n"), entry.th32ProcessID);
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                if (!hProcess) {
                    _tprintf(TEXT("Failed to open process! %d\n"), GetLastError());
                    break;
                }

                void* data = VirtualAllocEx(hProcess, NULL, sizeof(shellcode) + sizeof(*d) + sizeof(rawData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (!data) {
                    _tprintf(TEXT("Failed to allocate memory! %d\n"), GetLastError());
                    CloseHandle(hProcess);
                    break;
                }
                _tprintf(TEXT("Memory allocated at %llX\n"), reinterpret_cast<unsigned long long>(data));
                void* rdata = data;
                void* idata = reinterpret_cast<void*>(reinterpret_cast<BYTE*>(data) + sizeof(rawData));
                void* ldata = reinterpret_cast<void*>(reinterpret_cast<BYTE*>(idata) + sizeof(*d));

                WriteProcessMemory(hProcess, rdata, rawData, sizeof(rawData), NULL);

                *reinterpret_cast<void**>(reinterpret_cast<CHAR*>(shellcode) + 2) = reinterpret_cast<void*>(0x7FFE85925DA0);
                *reinterpret_cast<void**>(reinterpret_cast<CHAR*>(shellcode) + 12) = reinterpret_cast<void*>(0x7FFDDC200100);
                *reinterpret_cast<void**>(reinterpret_cast<CHAR*>(shellcode) + 38) = reinterpret_cast<void*>(idata);
                WriteProcessMemory(hProcess, ldata, shellcode, sizeof(shellcode), NULL);
                d->data = rdata;
                WriteProcessMemory(hProcess, idata, d, sizeof(*d), NULL);

                _tprintf(TEXT("ldata at %llX\n"), reinterpret_cast<unsigned long long>(ldata));

                //WriteProcessMemory(hProcess, idata, &d, sizeof(d), NULL);
                //HANDLE hThread = CreateRemoteThreadEx(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(ldata), 0, 0, 0, 0);
                /*if (hThread) {
                    WaitForSingleObject(hThread, 1000);
                }
                VirtualFreeEx(hProcess, data, 0, MEM_RELEASE);*/

                CloseHandle(hProcess);
            }
        }
    }

    CloseHandle(snapshot);

    /*d->data = rawData;

    static DWORD64 test = reinterpret_cast<DWORD64>(&orig);

    
    void* code = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(code, shellcode, sizeof(shellcode));

    *reinterpret_cast<void**>(reinterpret_cast<CHAR*>(code) + 2) = reinterpret_cast<void*>(&orig);
    *reinterpret_cast<void**>(reinterpret_cast<CHAR*>(code) + 12) = reinterpret_cast<void*>(&test);
    *reinterpret_cast<void**>(reinterpret_cast<CHAR*>(code) + 38) = reinterpret_cast<void*>(d);


    
    _tprintf(TEXT("test1 0x%llX!\n"), test);
    ((void(*)(int))test)(1);
    ((void(*)(int))test)(1);
    ((void(*)(int))test)(1);

    test = reinterpret_cast<DWORD64>(code);

    _tprintf(TEXT("test2 0x%llX!\n"), test);
    ((void(*)(int))test)(2);
    ((void(*)(int))test)(2);
    ((void(*)(int))test)(2);


    _tprintf(TEXT("test3 0x%llX!\n"), test);
    ((void(*)(int))test)(3);
    ((void(*)(int))test)(3);
    ((void(*)(int))test)(3);*/




    //CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(code), 0, 0, 0);
    //inject(d);
    system("pause");
	return 0;

}	
