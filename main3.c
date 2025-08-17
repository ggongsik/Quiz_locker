// FIX: Defined UNICODE to ensure all Windows APIs use wide-characters
#define UNICODE
// _UNICODE is often defined by the compiler flags, so removed from here to prevent redefinition warnings.
/**
 * @file main3.c
 * @brief A hardened reverse engineering challenge with obfuscation and anti-tampering.
 * @dependencies sha256.c, sha256.h
 * @build-command (MinGW GCC) gcc -DUNICODE -D_UNICODE quiz_program_hardened.c sha256.c -o challenge.exe -lgdi32 -lshell32 -s -O2 -mwindows
 */
#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <windows.h>
#include <shlobj.h>
#include <wchar.h>
#include <wctype.h>

// FIX: Re-added manual PEB definitions to remove dependency on winternl.h which is missing in some MinGW environments.
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InMemoryOrderLinks; PVOID DllBase; UNICODE_STRING FullDllName; } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA { LIST_ENTRY InMemoryOrderModuleList; } PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _PEB { BOOLEAN BeingDebugged; PPEB_LDR_DATA Ldr; } PEB, *PPEB;


#include "sha256.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

// === [Anti-Reversing] TSC read for timing checks (GCC/MSVC compatible) ===
#ifdef __GNUC__
__inline__ unsigned long long read_tsc(void) { unsigned long long val; __asm__ __volatile__ ("rdtsc" : "=A" (val)); return val; }
#else
#include <intrin.h>
#define read_tsc __rdtsc
#endif

// === Control IDs ===
#define IDC_PROMPT_STATIC 101
#define IDC_ANSWER_EDIT   102
#define IDC_SUBMIT_BUTTON 103

// === [Anti-Reversing: API Obfuscation] Function pointer definitions ===
typedef HMODULE(WINAPI* LoadLibraryW_t)(LPCWSTR); typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
typedef int(WINAPI* MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT); typedef HWND(WINAPI* CreateWindowExW_t)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
typedef LRESULT(WINAPI* DefWindowProcW_t)(HWND, UINT, WPARAM, LPARAM); typedef ATOM(WINAPI* RegisterClassW_t)(const WNDCLASSW*);
typedef BOOL(WINAPI* ShowWindow_t)(HWND, int); typedef BOOL(WINAPI* GetMessageW_t)(LPMSG, HWND, UINT, UINT);
typedef BOOL(WINAPI* TranslateMessage_t)(const MSG*); typedef LRESULT(WINAPI* DispatchMessageW_t)(const MSG*);
typedef HGDIOBJ(WINAPI* CreateFontW_t)(int, int, int, int, int, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPCWSTR);
typedef HBRUSH(WINAPI* CreateSolidBrush_t)(COLORREF); typedef LRESULT(WINAPI* SendMessageW_t)(HWND, UINT, WPARAM, LPARAM);
typedef LONG_PTR(WINAPI* SetWindowLongPtrW_t)(HWND, int, LONG_PTR); typedef HGDIOBJ(WINAPI* GetStockObject_t)(int);
typedef COLORREF(WINAPI* SetTextColor_t)(HDC, COLORREF); typedef int(WINAPI* SetBkMode_t)(HDC, int);
typedef BOOL(WINAPI* DeleteObject_t)(HGDIOBJ); typedef void(WINAPI* PostQuitMessage_t)(int);
typedef LRESULT(WINAPI* CallWindowProcW_t)(WNDPROC, HWND, UINT, WPARAM, LPARAM); typedef int(WINAPI* GetWindowTextW_t)(HWND, LPWSTR, int);
typedef int(WINAPI* WideCharToMultiByte_t)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL); typedef BOOL(WINAPI* SetWindowTextW_t)(HWND, LPCWSTR);
typedef HWND(WINAPI* GetParent_t)(HWND); typedef BOOL(WINAPI* DestroyWindow_t)(HWND);
typedef HCURSOR(WINAPI* LoadCursorW_t)(HINSTANCE, LPCWSTR); typedef BOOL(WINAPI* IsDebuggerPresent_t)(VOID);
typedef void(WINAPI* ExitProcess_t)(UINT); typedef BOOL(WINAPI* GetModuleFileNameW_t)(HMODULE, LPWSTR, DWORD);
typedef BOOL(WINAPI* ShellExecuteExW_t)(SHELLEXECUTEINFOW*); typedef BOOL(WINAPI* OpenProcessToken_t)(HANDLE, DWORD, PHANDLE);
typedef BOOL(WINAPI* GetTokenInformation_t)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD); typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
typedef HWND(WINAPI* SetFocus_t)(HWND);

// A single struct to hold all our resolved API function pointers.
struct {
    GetProcAddress_t GetProcAddress; LoadLibraryW_t LoadLibraryW; MessageBoxW_t MessageBoxW; CreateWindowExW_t CreateWindowExW; DefWindowProcW_t DefWindowProcW;
    RegisterClassW_t RegisterClassW; ShowWindow_t ShowWindow; GetMessageW_t GetMessageW; TranslateMessage_t TranslateMessage; DispatchMessageW_t DispatchMessageW;
    CreateFontW_t CreateFontW; CreateSolidBrush_t CreateSolidBrush; SendMessageW_t SendMessageW; SetWindowLongPtrW_t SetWindowLongPtrW; GetStockObject_t GetStockObject;
    SetTextColor_t SetTextColor; SetBkMode_t SetBkMode; DeleteObject_t DeleteObject; PostQuitMessage_t PostQuitMessage; CallWindowProcW_t CallWindowProcW;
    GetWindowTextW_t GetWindowTextW; WideCharToMultiByte_t WideCharToMultiByte; SetWindowTextW_t SetWindowTextW; GetParent_t GetParent; DestroyWindow_t DestroyWindow;
    LoadCursorW_t LoadCursorW; IsDebuggerPresent_t IsDebuggerPresent; ExitProcess_t ExitProcess; GetModuleFileNameW_t GetModuleFileNameW; ShellExecuteExW_t ShellExecuteExW;
    OpenProcessToken_t OpenProcessToken; GetTokenInformation_t GetTokenInformation; CloseHandle_t CloseHandle; SetFocus_t SetFocus;
} Api;

// === [Anti-Reversing] Security Globals ===
BOOL g_is_compromised = FALSE;
DWORD_PTR g_golden_checksum = 0;

// === [Anti-Reversing: String Encryption] ===
const char XOR_KEY[] = "ReversingChallengeIsFun";
void DecryptW(wchar_t* data, size_t count) {
    if (g_is_compromised) return;
    char* p = (char*)data;
    for (size_t i = 0; i < count * sizeof(wchar_t); ++i) {
        p[i] ^= XOR_KEY[i % (sizeof(XOR_KEY) - 1)];
    }
}

// === [Anti-Reversing: Encrypted Strings] ===
wchar_t ENC_Q1[] = { 0x0013, 0x0031, 0x002e, 0x0020, 0xc11c, 0xc128, 0x0020, 0x003c, 0xb0a0, 0xac1c, 0x003e, 0x0028, 0xc800, 0xc790, 0x003a, 0x0020, 0xc774, 0xc0c1, 0x0029, 0xc758, 0x0020, 0xccab, 0x0020, 0xbb58, 0xc7a5, 0xc744, 0x0020, 0xae30, 0x0020, 0xae08, 0xc220, 0xc224, 0xc624, 0xc62c, 0x002e };
wchar_t ENC_Q2[] = { 0x0013, 0x0032, 0x002e, 0x0020, 0xc22c, 0xb97c, 0xb958, 0xb274, 0x0020, 0xb300, 0xc81c, 0x0020, 0xc758, 0x0020, 0xac8c, 0x0020, 0xc774, 0xb98c, 0xc740, 0x0020, 0xbb58, 0xc5b4, 0xc2e0, 0xac00, 0xac00, 0x003f };
wchar_t ENC_Q3[] = { 0x0013, 0x0033, 0x002e, 0x0020, 0xbcf4, 0xcf5c, 0xb85c, 0xc774, 0xb4dc, 0x0020, 0x0027, 0xcf54, 0xc0ac, 0xb12c, 0x0020, 0xd14c, 0xd14c, 0x0027, 0xc758, 0x0020, 0xacf5, 0xc2dd, 0x0020, 0xc124, 0xc815, 0xc0c1, 0x0020, 0xc120, 0xd638, 0x0020, 0xc2dd, 0xd488, 0xc740, 0x0020, 0xbb58, 0xc5b4, 0xc2e0, 0xac00, 0xac00, 0x003f };
wchar_t ENC_Q4[] = { 0x0013, 0x0034, 0x002e, 0x0020, 0xcf3c, 0xb4dc, 0xb975, 0x0020, 0xb77c, 0xb958, 0xc758, 0x0020, 0xacf5, 0x0020, 0x0027, 0xd15c, 0xc81c, 0xac14, 0x0020, 0xb1c8, 0xd14c, 0x0020, 0xc5d4, 0x0020, 0xac00, 0x0027, 0x0020, 0xb3c4, 0xc775, 0xc5d4, 0xc758, 0x0020, 0xc2dd, 0xd53c, 0xd53c, 0xc775, 0xb4dc, 0x0020, 0xbb58, 0xc7a5, 0xc740, 0x0020, 0xbb58, 0xc5b4, 0xc2e0, 0xac00, 0xac00, 0x003f };
wchar_t ENC_Q5[] = { 0x0013, 0x0035, 0x002e, 0x0020, 0xc2dd, 0xc774, 0xb098, 0x0020, 0xb77c, 0xace0, 0xc758, 0x0020, 0x0031, 0xc9d5, 0x0020, 0xc815, 0xae34, 0x0020, 0xc568, 0xbc8c, 0xc758, 0x0020, 0xba85, 0xce5d, 0xc740, 0x0020, 0xbb58, 0xc5b4, 0xc2e0, 0xac00, 0xac00, 0x003f };
wchar_t ENC_Q6[] = { 0x0013, 0x0036, 0x002e, 0x0020, 0xd795, 0xc5d4, 0x0020, 0x0032, 0xbc1c, 0x002c, 0x0020, 0xb4dc, 0xc5d4, 0x0020, 0x0031, 0xbc1c, 0xc73c, 0x0020, 0xae30, 0xc131, 0xb4dc, 0x0020, 0xacf5, 0xc3d5, 0x0020, 0xc0ac, 0xcaca, 0xc220, 0xc758, 0x0020, 0xba85, 0xce5d, 0xc740, 0x0020, 0xbb58, 0xc5b4, 0xc2e0, 0xac00, 0xac00, 0x003f };
wchar_t ENC_Q7[] = { 0x0013, 0x0037, 0x002e, 0x0020, 0xbc84, 0xce74, 0xc568, 0x0020, 0xc720, 0xd14c, 0xbc84, 0x0020, 0x0027, 0xd638, 0xc2dd, 0xb958, 0xce5c, 0x0020, 0xc2dd, 0xc774, 0xc138, 0xc774, 0x0027, 0xc758, 0x0020, 0xc124, 0xc815, 0xc0c1, 0x0020, 0xc2dd, 0xc775, 0xc77c, 0xc740, 0x0020, 0xc5b8, 0xc81c, 0xc778, 0xac00, 0x003f, 0x0020, 0x0028, 0xd795, 0xc2dd, 0x003a, 0x0020, 0x004e, 0xc6d4, 0x0020, 0x004e, 0xc77c, 0x0029 };
wchar_t ENC_Q8[] = { 0x0013, 0x0038, 0x002e, 0x0020, 0xbc54, 0xb4dc, 0x0020, 0x0027, 0xc9d9, 0xd14c, 0xb958, 0xc694, 0x0027, 0xc758, 0x0020, 0xbcac, 0xcf5c, 0x0020, 0x0041, 0x0043, 0x0041, 0x306d, 0xc758, 0x0020, 0xbc1c, 0xb824, 0x0020, 0xace0, 0xc591, 0xc774, 0x0020, 0xc774, 0xb98c, 0xc740, 0x0020, 0xbb58, 0xc5b4, 0xc2e0, 0xac00, 0xac00, 0x003f };
wchar_t ENC_Q9[] = { 0x0013, 0x0039, 0x002e, 0x0020, 0xc11c, 0xc0ac, 0xc2dc, 0x0020, 0x003c, 0xc624, 0xb57b, 0xc138, 0xc774, 0xc544, 0x003e, 0xc758, 0x0020, 0xc8fc, 0xc778, 0xacf5, 0x0020, 0xc624, 0xb514, 0xc138, 0xc6b0, 0xc2a4, 0xac00, 0x0020, 0xace0, 0xd5a5, 0xc744, 0x0020, 0xb530, 0xb098, 0xc788, 0xb358, 0x0020, 0xcd1d, 0x0020, 0xae30, 0xac04, 0xc740, 0x0020, 0xba87, 0x0020, 0xb144, 0xc778, 0xac00, 0x003f, 0x0020, 0x0028, 0xd795, 0xc2dd, 0x003a, 0x0020, 0x004e, 0xb144, 0x0029 };
wchar_t ENC_Q10[] = { 0x0013, 0x0031, 0x0030, 0x002e, 0x0020, 0xb2c8, 0xccb4, 0x0020, 0xcc9c, 0xd559, 0xc5d0, 0xc11c, 0x0020, 0x0027, 0xcd08, 0xc778, 0x0027, 0xc744, 0x0020, 0xc758, 0xbbf8, 0xd558, 0xb294, 0x0020, 0xb3c5, 0xc77c, 0xc5b4, 0x0020, 0xc6a9, 0xc5b4, 0xb294, 0x0020, 0xbb58, 0xc5b4, 0xc2e0, 0xac00, 0xac00, 0x003f };
wchar_t ENC_RUNAS[] = { 0x0012, 0x0015, 0x000e, 0x0001, 0x0013 };
wchar_t ENC_ADMIN_FAIL_MSG[] = { 0xad00, 0xb9ac, 0xc790, 0x0020, 0xad8c, 0xd55c, 0xb85c, 0x0020, 0xd504, 0xb85c, 0xadf8, 0xb7a8, 0xb7a8, 0xc744, 0x0020, 0xb2e4, 0xc2dc, 0x0020, 0xc2dc, 0xc791, 0xd558, 0xb294, 0x0020, 0xb370, 0x0020, 0xc2e4, 0xd328, 0xd588, 0xc2b5, 0xb2c8, 0x002e };
wchar_t ENC_ERROR_TITLE[] = { 0xc624, 0xb95c };
wchar_t ENC_CLASS_NAME[] = { 0x0028, 0x0001, 0x0003, 0x000b, 0x0005, 0x0012, 0x0017, 0x0009, 0x000e, 0x0004, 0x0017, 0x0003, 0x000c, 0x0001, 0x0013, 0x0013 };
wchar_t ENC_WINDOW_TITLE[] = { 0x0033, 0x0019, 0x0013, 0x0014, 0x0005, 0x000d, 0x0020, 0x0001, 0x0015, 0x0014, 0x0008, 0x0005, 0x000e, 0x0014, 0x0009, 0x0003, 0x0001, 0x0014, 0x0009, 0x000f, 0x000e };
wchar_t ENC_FONT_NAME[] = { 0x0023, 0x000f, 0x000e, 0x0013, 0x000f, 0x000c, 0x0001, 0x0013 };
wchar_t ENC_SUBMIT_BUTTON[] = { 0xc81c, 0xcd9c };
wchar_t ENC_OK_MSG[] = { 0x0032, 0x0005, 0x0013, 0x0010, 0x000f, 0x000e, 0x0013, 0x0005, 0x0020, 0x0008, 0x0001, 0x0013, 0x0008, 0x0020, 0x000d, 0x0001, 0x0014, 0x0003, 0x0008, 0x0005, 0x0013, 0x002e };
wchar_t ENC_OK_TITLE[] = { 0xd655, 0xc778 };
wchar_t ENC_FAIL_MSG[] = { 0x0032, 0x0005, 0x0013, 0x0010, 0x000f, 0x000e, 0x0013, 0x0005, 0x0020, 0x0008, 0x0001, 0x0013, 0x0008, 0x0020, 0x000d, 0x0009, 0x0013, 0x000d, 0x0001, 0x0014, 0x0003, 0x0008, 0x002e };
wchar_t ENC_FAIL_TITLE[] = { 0xc2e4, 0xd328 };
wchar_t ENC_REPORT_TITLE[] = { 0xacb0, 0xace0 };
wchar_t ENC_SUCCESS_MSG[] = { 0xc2dc, 0xc2a4, 0xd15c, 0x0020, 0xc7a0, 0xae08, 0xc774, 0x0020, 0xd574, 0xc81c, 0xb418, 0xc2b5, 0xb2c8, 0x002e };
wchar_t ENC_SUCCESS_TITLE[] = { 0xc811, 0xc18d, 0x0020, 0xd5c8, 0xc6a9 };
wchar_t ENC_DENIED_MSG[] = { 0xc0ac, 0xc6a9, 0xc790, 0x0020, 0xc778, 0xc99d, 0xc5d0, 0x0020, 0xc2e4, 0xd328, 0xd588, 0xc2b5, 0xb2c8, 0x002e, 0x0020, 0xc2dc, 0xc2a4, 0xd15c, 0xc740, 0x0020, 0xc7a0, 0xae34, 0x0020, 0xc0c1, 0xd0dc, 0xb85c, 0x0020, 0xc720, 0xc9c0, 0xb429, 0xb2c8, 0x002e };
wchar_t ENC_DENIED_TITLE[] = { 0xc811, 0xc18d, 0x0020, 0xac70, 0xbd80 };

// === Quiz Database ===
typedef struct { char* enc_prompt; size_t prompt_size; const char* answer_hash; } QuizItem;
QuizItem QUIZ_DATABASE[] = {
    {(char*)ENC_Q1, sizeof(ENC_Q1), "c3cbdc4b90f1a2cb3c0a2ddd5178eec770c092a6276a9790f749aff6049a23d1"},
    {(char*)ENC_Q2, sizeof(ENC_Q2), "b9d3750f19bf73d9b6ff84e5fbdeb662fcc4e6fa9ca3a8e44ccfd9c71c62bfdc"},
    {(char*)ENC_Q3, sizeof(ENC_Q3), "d948cdcae36242d857d00541b080a9cb3ee9a56d7006b286c8ec88a53644b47a"},
    {(char*)ENC_Q4, sizeof(ENC_Q4), "5f2ee1dbff8a19a920c97c1c3b2a5b68e7abbbf99b06f965592e7d5b3dea28fa"},
    {(char*)ENC_Q5, sizeof(ENC_Q5), "671243a1e7fabdd461849293701d1348c0e2a4c856217ccbf0953b7b4b391fea"},
    {(char*)ENC_Q6, sizeof(ENC_Q6), "2145d92188dda91d6da660811af8698d722fb06419867f93771ee1c6214d1bd2"},
    {(char*)ENC_Q7, sizeof(ENC_Q7), "3c94c166318daa3c0a22a1f2f157492e9c9268abb088e8c2c66a4631cdd2dafc"},
    {(char*)ENC_Q8, sizeof(ENC_Q8), "3ebee2da2936a8344968c0bd5e55c21dfe54ce43f919c8194f2963f72e128642"},
    {(char*)ENC_Q9, sizeof(ENC_Q9), "277d0092147694027c3882afc0b81d1b59d56c3a6d5e032b6f53ec244b16f70f"},
    {(char*)ENC_Q10, sizeof(ENC_Q10), "2e87834fde8b6d490ccfb121a24bb40c96a377f58845d4c569ce503f3476ce2a"}
};
const int QUIZ_COUNT = 10;

// === Global Variables ===
HINSTANCE g_hInst; HWND g_hMainWnd, g_hPrompt, g_hEdit, g_hButton; HFONT g_hFont; HBRUSH g_hBgBrush; WNDPROC g_OriginalEditProc; int g_current_quiz_index = 0; int g_score = 0;

// Function Prototypes
void ResolveAllApis();
DWORD_PTR CalculateChecksum(const BYTE* start, size_t size);
void InitializeAndProtect();
void AntiTamperCheck();
void AntiDebugCheck();
void OnSubmitClicked_Start();
void OnSubmitClicked(HWND hwnd);
void OnSubmitClicked_End();
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK EditSubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void LiberationProtocol();
void ManageNetworkAdapters(BOOL enable);
void ReEnableNetworkAdapters(void);
void lock_initial_file();
void DisplayCurrentQuestion();
void UpdateWindowTitle();

// === [Anti-Reversing: API Obfuscation] More stable API resolving ===
void ResolveAllApis() {
    // A more stable way to get API addresses.
    // First, get a handle to kernel32.dll, which is always loaded.
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    // If we can't even get kernel32, something is very wrong. Exit immediately.
    // We can't use our Api.ExitProcess yet, so we call the real one.
    if (!hKernel32) ExitProcess(1);

    // Get the address of GetProcAddress and LoadLibraryW themselves.
    Api.GetProcAddress = (GetProcAddress_t)GetProcAddress(hKernel32, "GetProcAddress");
    Api.LoadLibraryW = (LoadLibraryW_t)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!Api.GetProcAddress || !Api.LoadLibraryW) ExitProcess(1);

    // Now, load other libraries and get function pointers.
    HMODULE hUser32 = Api.LoadLibraryW(L"user32.dll");
    HMODULE hGdi32 = Api.LoadLibraryW(L"gdi32.dll");
    HMODULE hShell32 = Api.LoadLibraryW(L"shell32.dll");
    HMODULE hAdvapi32 = Api.LoadLibraryW(L"advapi32.dll");
    
    // Now we can use our own Api.ExitProcess for subsequent checks
    Api.ExitProcess = (ExitProcess_t)Api.GetProcAddress(hKernel32, "ExitProcess");
    if (!hUser32 || !hGdi32 || !hShell32 || !hAdvapi32 || !Api.ExitProcess) Api.ExitProcess(1);

    // Resolve all other necessary functions
    Api.IsDebuggerPresent = (IsDebuggerPresent_t)Api.GetProcAddress(hKernel32, "IsDebuggerPresent");
    Api.GetModuleFileNameW = (GetModuleFileNameW_t)Api.GetProcAddress(hKernel32, "GetModuleFileNameW");
    Api.CloseHandle = (CloseHandle_t)Api.GetProcAddress(hKernel32, "CloseHandle");
    Api.WideCharToMultiByte = (WideCharToMultiByte_t)Api.GetProcAddress(hKernel32, "WideCharToMultiByte");
    
    Api.OpenProcessToken = (OpenProcessToken_t)Api.GetProcAddress(hAdvapi32, "OpenProcessToken");
    Api.GetTokenInformation = (GetTokenInformation_t)Api.GetProcAddress(hAdvapi32, "GetTokenInformation");

    Api.MessageBoxW = (MessageBoxW_t)Api.GetProcAddress(hUser32, "MessageBoxW");
    Api.CreateWindowExW = (CreateWindowExW_t)Api.GetProcAddress(hUser32, "CreateWindowExW");
    Api.DefWindowProcW = (DefWindowProcW_t)Api.GetProcAddress(hUser32, "DefWindowProcW");
    Api.RegisterClassW = (RegisterClassW_t)Api.GetProcAddress(hUser32, "RegisterClassW");
    Api.ShowWindow = (ShowWindow_t)Api.GetProcAddress(hUser32, "ShowWindow");
    Api.GetMessageW = (GetMessageW_t)Api.GetProcAddress(hUser32, "GetMessageW");
    Api.TranslateMessage = (TranslateMessage_t)Api.GetProcAddress(hUser32, "TranslateMessage");
    Api.DispatchMessageW = (DispatchMessageW_t)Api.GetProcAddress(hUser32, "DispatchMessageW");
    Api.SendMessageW = (SendMessageW_t)Api.GetProcAddress(hUser32, "SendMessageW");
    Api.SetWindowLongPtrW = (SetWindowLongPtrW_t)Api.GetProcAddress(hUser32, "SetWindowLongPtrW");
    Api.PostQuitMessage = (PostQuitMessage_t)Api.GetProcAddress(hUser32, "PostQuitMessage");
    Api.CallWindowProcW = (CallWindowProcW_t)Api.GetProcAddress(hUser32, "CallWindowProcW");
    Api.GetWindowTextW = (GetWindowTextW_t)Api.GetProcAddress(hUser32, "GetWindowTextW");
    Api.SetWindowTextW = (SetWindowTextW_t)Api.GetProcAddress(hUser32, "SetWindowTextW");
    Api.GetParent = (GetParent_t)Api.GetProcAddress(hUser32, "GetParent");
    Api.DestroyWindow = (DestroyWindow_t)Api.GetProcAddress(hUser32, "DestroyWindow");
    Api.LoadCursorW = (LoadCursorW_t)Api.GetProcAddress(hUser32, "LoadCursorW");
    Api.SetFocus = (SetFocus_t)Api.GetProcAddress(hUser32, "SetFocus");

    Api.CreateFontW = (CreateFontW_t)Api.GetProcAddress(hGdi32, "CreateFontW");
    Api.CreateSolidBrush = (CreateSolidBrush_t)Api.GetProcAddress(hGdi32, "CreateSolidBrush");
    Api.GetStockObject = (GetStockObject_t)Api.GetProcAddress(hGdi32, "GetStockObject");
    Api.SetTextColor = (SetTextColor_t)Api.GetProcAddress(hGdi32, "SetTextColor");
    Api.SetBkMode = (SetBkMode_t)Api.GetProcAddress(hGdi32, "SetBkMode");
    Api.DeleteObject = (DeleteObject_t)Api.GetProcAddress(hGdi32, "DeleteObject");

    Api.ShellExecuteExW = (ShellExecuteExW_t)Api.GetProcAddress(hShell32, "ShellExecuteExW");
}

// === [Anti-Reversing: Code Integrity] ===
DWORD_PTR CalculateChecksum(const BYTE* start, size_t size) { DWORD_PTR c = 0; for (size_t i = 0; i < size; ++i) { c = (c >> 1) + ((c & 1) << 15); c += start[i]; } return c; }
void InitializeAndProtect() { 
    // FIX: Call to AntiDebugCheck is kept, but its content is disabled to prevent silent exits.
    AntiDebugCheck(); 
    size_t s = (BYTE*)OnSubmitClicked_End - (BYTE*)OnSubmitClicked_Start; 
    g_golden_checksum = CalculateChecksum((BYTE*)OnSubmitClicked_Start, s); 
}
void AntiTamperCheck() { 
    // FIX: The logic that could cause a silent exit has been disabled.
    // if(g_is_compromised) return; 
    // size_t s = (BYTE*)OnSubmitClicked_End-(BYTE*)OnSubmitClicked_Start; 
    // if(CalculateChecksum((BYTE*)OnSubmitClicked_Start, s) != g_golden_checksum) g_is_compromised = TRUE; 
}

// === [Anti-Reversing: Anti-Debugging] ===
void AntiDebugCheck() {
    // FIX: The logic that could cause a silent exit has been disabled.
    // if (g_is_compromised) return;
    // if (Api.IsDebuggerPresent()) { g_is_compromised = TRUE; return; }
}

BOOL IsRunningAsAdmin(void) { BOOL f = FALSE; HANDLE h = NULL; TOKEN_ELEVATION e; DWORD s; if (Api.OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &h)) { if (Api.GetTokenInformation(h, TokenElevation, &e, sizeof(e), &s)) f = e.TokenIsElevated; } if (h) Api.CloseHandle(h); return f; }

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    MessageBoxW(0, L"프로그램 시작!", L"DEBUG", 0);
    g_hInst = hInstance; ResolveAllApis(); InitializeAndProtect();
    MessageBoxW(0, L"api 확인 시작!", L"DEBUG", 0);
    if (!IsRunningAsAdmin()) {
        wchar_t szPath[MAX_PATH]; if (Api.GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath))) {
            SHELLEXECUTEINFOW sei = { sizeof(sei) }; 
            wchar_t runas_verb[6]; memcpy(runas_verb, ENC_RUNAS, sizeof(ENC_RUNAS)); DecryptW(runas_verb, 5); runas_verb[5] = L'\0';
            sei.lpVerb = runas_verb; sei.lpFile = szPath; sei.nShow = SW_NORMAL;
            if (!Api.ShellExecuteExW(&sei)) {
                wchar_t admin_fail_msg[31]; memcpy(admin_fail_msg, ENC_ADMIN_FAIL_MSG, sizeof(ENC_ADMIN_FAIL_MSG)); DecryptW(admin_fail_msg, 30); admin_fail_msg[30] = L'\0';
                wchar_t error_title[3]; memcpy(error_title, ENC_ERROR_TITLE, sizeof(ENC_ERROR_TITLE)); DecryptW(error_title, 2); error_title[2] = L'\0';
                Api.MessageBoxW(NULL, admin_fail_msg, error_title, MB_OK | MB_ICONERROR);
            }
        } return 1;
    }
    
    ManageNetworkAdapters(FALSE); 
    atexit(ReEnableNetworkAdapters); 
    lock_initial_file();
    WNDCLASSW wc = {0}; 
    wchar_t class_name[17]; memcpy(class_name, ENC_CLASS_NAME, sizeof(ENC_CLASS_NAME)); DecryptW(class_name, 16); class_name[16] = L'\0';
    wc.lpfnWndProc = WindowProc; wc.hInstance = hInstance; wc.lpszClassName = class_name;
    wc.hbrBackground = Api.CreateSolidBrush(RGB(15, 15, 15)); 
    wc.hCursor = Api.LoadCursorW(NULL, IDC_ARROW); 
    Api.RegisterClassW(&wc);
    
    wchar_t window_title[22]; memcpy(window_title, ENC_WINDOW_TITLE, sizeof(ENC_WINDOW_TITLE)); DecryptW(window_title, 21); window_title[21] = L'\0';
    g_hMainWnd = Api.CreateWindowExW(0, class_name, window_title, WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 800, 240, NULL, NULL, hInstance, NULL);
    if (g_hMainWnd == NULL) {
    DWORD dwError = GetLastError();
    wchar_t error_msg[256];
    _snwprintf(error_msg, 256, L"CreateWindowExW 실패!\n오류 코드: %lu", dwError);
    Api.MessageBoxW(NULL, error_msg, L"치명적 오류", MB_OK | MB_ICONERROR);
    return 0; // 원래 코드
}
    //if (g_hMainWnd == NULL) return 0;
    Api.ShowWindow(g_hMainWnd, nCmdShow);
    MSG msg = {0}; int msg_count = 0;
    while (Api.GetMessageW(&msg, NULL, 0, 0) > 0) {
        // The periodic checks are also disabled by disabling the functions they call.
        if (!g_is_compromised && ++msg_count > 100) { /*AntiTamperCheck();*/ AntiDebugCheck(); msg_count = 0; }
        Api.TranslateMessage(&msg); Api.DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            wchar_t font_name[9]; memcpy(font_name, ENC_FONT_NAME, sizeof(ENC_FONT_NAME)); DecryptW(font_name, 8); font_name[8] = L'\0';
            g_hFont = Api.CreateFontW(20, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, FIXED_PITCH, font_name);
            g_hBgBrush = Api.CreateSolidBrush(RGB(25, 25, 25));
            g_hPrompt = Api.CreateWindowExW(0, L"STATIC", L"", WS_CHILD|WS_VISIBLE, 20, 20, 740, 50, hwnd, (HMENU)IDC_PROMPT_STATIC, g_hInst, NULL);
            g_hEdit = Api.CreateWindowExW(0, L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 20, 80, 520, 30, hwnd, (HMENU)IDC_ANSWER_EDIT, g_hInst, NULL);
            
            wchar_t submit_text[3]; memcpy(submit_text, ENC_SUBMIT_BUTTON, sizeof(ENC_SUBMIT_BUTTON)); DecryptW(submit_text, 2); submit_text[2] = L'\0';
            g_hButton = Api.CreateWindowExW(0, L"BUTTON", submit_text, WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 550, 80, 100, 30, hwnd, (HMENU)IDC_SUBMIT_BUTTON, g_hInst, NULL);
            
            Api.SendMessageW(g_hPrompt, WM_SETFONT, (WPARAM)g_hFont, TRUE); Api.SendMessageW(g_hEdit, WM_SETFONT, (WPARAM)g_hFont, TRUE); Api.SendMessageW(g_hButton, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            g_OriginalEditProc = (WNDPROC)Api.SetWindowLongPtrW(g_hEdit, GWLP_WNDPROC, (LONG_PTR)EditSubclassProc);
            DisplayCurrentQuestion(); Api.SetFocus(g_hEdit); break;
        }
        case WM_CTLCOLORSTATIC: { HDC h = (HDC)wParam; Api.SetTextColor(h, RGB(0,255,128)); Api.SetBkMode(h, TRANSPARENT); return (LRESULT)Api.GetStockObject(NULL_BRUSH); }
        case WM_CTLCOLOREDIT: { HDC h = (HDC)wParam; Api.SetTextColor(h, RGB(220,220,220)); SetBkColor(h, RGB(25, 25, 25)); return (LRESULT)g_hBgBrush; }
        case WM_CTLCOLORBTN: { return (LRESULT)Api.GetStockObject(DC_BRUSH); }
        case WM_COMMAND: { if (LOWORD(wParam) == IDC_SUBMIT_BUTTON) { OnSubmitClicked(hwnd); } break; } // Removed AntiTamperCheck call from here for stability
        case WM_DESTROY: { Api.DeleteObject(g_hFont); Api.DeleteObject(g_hBgBrush); Api.PostQuitMessage(0); break; }
    }
    return Api.DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK EditSubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_KEYDOWN && wParam == VK_RETURN) { Api.SendMessageW(Api.GetParent(hwnd), WM_COMMAND, MAKEWPARAM(IDC_SUBMIT_BUTTON, BN_CLICKED), (LPARAM)g_hButton); return 0; }
    return Api.CallWindowProcW(g_OriginalEditProc, hwnd, uMsg, wParam, lParam);
}

void OnSubmitClicked_Start() {}
void OnSubmitClicked(HWND hwnd) {
    if (g_is_compromised) { g_score = -999; return; } if (g_current_quiz_index >= QUIZ_COUNT) return; // Kept check here
    wchar_t user_answer_wide[256]; Api.GetWindowTextW(g_hEdit, user_answer_wide, 256);
    wchar_t normalized_wide[256] = {0}; wchar_t* w = normalized_wide; const wchar_t* r = user_answer_wide;
    while (*r && (w - normalized_wide < 255)) { if (iswalnum(*r)) *w++ = towlower(*r); r++; } *w = L'\0';
    char user_answer_utf8[512] = {0}; Api.WideCharToMultiByte(CP_UTF8, 0, normalized_wide, -1, user_answer_utf8, 512, NULL, NULL);
    char salted_answer[1024]; char salt[] = "a1eph_nu11_is_running_n0w"; snprintf(salted_answer, 1024, "%s%s", user_answer_utf8, salt);
    BYTE hash_result[32]; char answer_hash_hex[65]; sha256_string(salted_answer, hash_result);
    for(int j=0; j<32; ++j) sprintf(answer_hash_hex + (j*2), "%02x", hash_result[j]);
    if (strcmp(answer_hash_hex, QUIZ_DATABASE[g_current_quiz_index].answer_hash) == 0) { g_score++;
        wchar_t ok_msg[23]; memcpy(ok_msg, ENC_OK_MSG, sizeof(ENC_OK_MSG)); DecryptW(ok_msg, 22); ok_msg[22] = L'\0';
        wchar_t ok_title[3]; memcpy(ok_title, ENC_OK_TITLE, sizeof(ENC_OK_TITLE)); DecryptW(ok_title, 2); ok_title[2] = L'\0';
        Api.MessageBoxW(hwnd, ok_msg, ok_title, MB_OK | MB_ICONINFORMATION);
    } else { 
        wchar_t fail_msg[24]; memcpy(fail_msg, ENC_FAIL_MSG, sizeof(ENC_FAIL_MSG)); DecryptW(fail_msg, 23); fail_msg[23] = L'\0';
        wchar_t fail_title[3]; memcpy(fail_title, ENC_FAIL_TITLE, sizeof(ENC_FAIL_TITLE)); DecryptW(fail_title, 2); fail_title[2] = L'\0';
        Api.MessageBoxW(hwnd, fail_msg, fail_title, MB_OK | MB_ICONERROR); 
    }
    g_current_quiz_index++; Api.SetWindowTextW(g_hEdit, L"");
    if (g_current_quiz_index < QUIZ_COUNT) { DisplayCurrentQuestion();
    } else {
        wchar_t final_msg[256]; _snwprintf(final_msg, 256, L"Authentication protocol complete.\nFinal score: %d/%d", g_score, QUIZ_COUNT);
        wchar_t report_title[3]; memcpy(report_title, ENC_REPORT_TITLE, sizeof(ENC_REPORT_TITLE)); DecryptW(report_title, 2); report_title[2] = L'\0';
        Api.MessageBoxW(hwnd, final_msg, report_title, MB_OK);
        if (g_score >= 7) { LiberationProtocol();
            wchar_t success_msg[15]; memcpy(success_msg, ENC_SUCCESS_MSG, sizeof(ENC_SUCCESS_MSG)); DecryptW(success_msg, 14); success_msg[14] = L'\0';
            wchar_t success_title[5]; memcpy(success_title, ENC_SUCCESS_TITLE, sizeof(ENC_SUCCESS_TITLE)); DecryptW(success_title, 4); success_title[4] = L'\0';
            Api.MessageBoxW(hwnd, success_msg, success_title, MB_OK);
        } else { 
            wchar_t denied_msg[33]; memcpy(denied_msg, ENC_DENIED_MSG, sizeof(ENC_DENIED_MSG)); DecryptW(denied_msg, 32); denied_msg[32] = L'\0';
            wchar_t denied_title[5]; memcpy(denied_title, ENC_DENIED_TITLE, sizeof(ENC_DENIED_TITLE)); DecryptW(denied_title, 4); denied_title[4] = L'\0';
            Api.MessageBoxW(hwnd, denied_msg, denied_title, MB_OK | MB_ICONERROR); 
        }
        Api.DestroyWindow(hwnd);
    }
}
void OnSubmitClicked_End() {}

void DisplayCurrentQuestion() {
    if (g_current_quiz_index < QUIZ_COUNT) {
        size_t prompt_len = QUIZ_DATABASE[g_current_quiz_index].prompt_size / sizeof(wchar_t);
        wchar_t* prompt_buffer = (wchar_t*)malloc(QUIZ_DATABASE[g_current_quiz_index].prompt_size + sizeof(wchar_t));
        if (prompt_buffer) {
            memcpy(prompt_buffer, QUIZ_DATABASE[g_current_quiz_index].enc_prompt, QUIZ_DATABASE[g_current_quiz_index].prompt_size);
            DecryptW(prompt_buffer, prompt_len);
            prompt_buffer[prompt_len] = L'\0';
            Api.SetWindowTextW(g_hPrompt, prompt_buffer);
            free(prompt_buffer);
        }
        UpdateWindowTitle();
    }
}

void UpdateWindowTitle() { wchar_t t[128]; _snwprintf(t, 128, L"System Authentication - Q[%d/%d] | S:%d", g_current_quiz_index + 1, QUIZ_COUNT, g_score); Api.SetWindowTextW(g_hMainWnd, t); }
void LiberationProtocol() { char f[]="sandbox_test_file.txt", m[]="rb+"; FILE* h=fopen(f,m); if(!h)return; fseek(h,0,SEEK_END);long s=ftell(h);fseek(h,0,SEEK_SET); char* b=(char*)malloc(s);if(!b){fclose(h);return;} fread(b,1,s,h);for(long i=0;i<s;i++)b[i]^=(char)0xC7; fseek(h,0,SEEK_SET);fwrite(b,1,s,h);fclose(h);free(b); }
void lock_initial_file() { char f[]="sandbox_test_file.txt",w[]="w",r[]="rb+",t[]="This is a test data file."; FILE* h=fopen(f,w); if(h){fprintf(h,"%s",t);fclose(h);h=fopen(f,r);if(h){fseek(h,0,SEEK_END);long s=ftell(h);fseek(h,0,SEEK_SET);char*b=(char*)malloc(s);if(!b){fclose(h);return;} fread(b,1,s,h);for(long i=0;i<s;++i)b[i]^=(char)0xC7; fseek(h,0,SEEK_SET);fwrite(b,1,s,h);fclose(h);free(b);}} }
void ManageNetworkAdapters(BOOL e) { const char*a=e?"enable":"disable";char c[256];const char*i[]={"Wi-Fi","이더넷","Ethernet","이더넷 2"};for(int n=0;n<ARRAYSIZE(i);++n){sprintf(c,"netsh interface set interface \"%s\" admin=%s",i[n],a);system(c);} }
void ReEnableNetworkAdapters(void) { ManageNetworkAdapters(TRUE); }
