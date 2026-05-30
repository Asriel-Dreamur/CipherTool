#define UNICODE
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <cstdint>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include "../core/cipher_scheme.h"
#include "../core/cipher_engine.h"

#pragma comment(lib, "comctl32.lib")

//Аватарка. Пока что не работает
const unsigned char fallback_ico[] = {
    0x00,0x00,0x01,0x00,0x01,0x00,0x20,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0xE8,0x02,
    0x00,0x00,0x16,0x00,0x00,0x00,0x28,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x40,0x00,
    0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x80,0x02,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,
    0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,
    0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string result(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &result[0], len, NULL, NULL);
    return result;
}

std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring result(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], len);
    return result;
}

std::string ExpandAlphabet(const std::string& input) {
    const std::string RUS = u8"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя";
    const std::string ENG = u8"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string result;
    std::istringstream iss(input);
    std::string token;
    while (std::getline(iss, token, '+')) {
        std::string clean;
        for (char c : token) if (!isspace((unsigned char)c)) clean += (char)tolower((unsigned char)c);
        if (clean == "rus") result += RUS;
        else if (clean == "eng") result += ENG;
        else result += token;
    }
    return result.empty() ? input : result;
}

void RegisterFileAssociation() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Classes\\.cipher", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return;
    }
    wchar_t exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    std::wstring appPath = L"\"" + std::wstring(exePath) + L"\" \"%1\"";
    if (RegCreateKeyEx(HKEY_CURRENT_USER, L"Software\\Classes\\.cipher", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, NULL, 0, REG_SZ, (BYTE*)L"CipherTool.Document", sizeof(L"CipherTool.Document"));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyEx(HKEY_CURRENT_USER, L"Software\\Classes\\CipherTool.Document\\shell\\open\\command", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, NULL, 0, REG_SZ, (BYTE*)appPath.c_str(), (DWORD)((appPath.size()+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

HWND hWndScheme, hTabControl;
HWND hLabelTextInput, hWndTextInput, hBtnEncryptText, hBtnDecryptText;
HWND hLabelTextOutput, hWndTextOutput;
HWND hLabelInputFile, hWndInput, hBtnBrowseInput;
HWND hLabelOutputFile, hWndOutput, hBtnBrowseOutput;
HWND hBtnEncryptFile, hBtnDecryptFile;
HWND hBtnEditScheme;

std::wstring schemeFilePath;
CipherScheme currentScheme;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK CreateSchemeWndProc(HWND, UINT, WPARAM, LPARAM);
void LoadScheme(const std::wstring& path);
void SaveScheme(const std::wstring& path, const CipherScheme& scheme);
void EncryptFile();
void DecryptFile();
void EncryptText();
void DecryptText();
void SwitchTab(int index);
void EnsureCipherExt(std::wstring& filePath);
void ResizeControls(HWND hWnd, int width, int height);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    InitCommonControls();
    RegisterFileAssociation();

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.lpszClassName = L"CipherToolClass";
    RegisterClass(&wc);

    WNDCLASS wcCreate = {0};
    wcCreate.lpfnWndProc = CreateSchemeWndProc;
    wcCreate.hInstance = hInstance;
    wcCreate.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wcCreate.lpszClassName = L"CreateSchemeClass";
    RegisterClass(&wcCreate);

    HWND hWnd = CreateWindow(L"CipherToolClass", L"CipherTool - Конструктор шифров",
                             WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                             700, 550, NULL, NULL, hInstance, NULL);
    if (!hWnd) return 0;
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    HICON hIcon = CreateIconFromResourceEx((PBYTE)fallback_ico, sizeof(fallback_ico), TRUE, 0x00030000, 0, 0, LR_DEFAULTCOLOR);
    if (hIcon) {
        SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    }

    int nArgs;
    LPWSTR* szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist && nArgs >= 2) {
        std::wstring possiblePath = szArglist[1];
        if (std::filesystem::exists(possiblePath) && possiblePath.size() >= 7 &&
            possiblePath.substr(possiblePath.size()-7) == L".cipher") {
            schemeFilePath = possiblePath;
            SetWindowText(hWndScheme, schemeFilePath.c_str());
            LoadScheme(schemeFilePath);
        }
    }
    if (szArglist) LocalFree(szArglist);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            CreateWindow(L"BUTTON", L"Открыть схему", WS_VISIBLE | WS_CHILD,
                         10, 10, 140, 30, hWnd, (HMENU)100, NULL, NULL);
            CreateWindow(L"BUTTON", L"Создать схему", WS_VISIBLE | WS_CHILD,
                         160, 10, 140, 30, hWnd, (HMENU)101, NULL, NULL);

            hBtnEditScheme = CreateWindow(L"BUTTON", L"Редактировать схему", WS_CHILD,
                                          310, 10, 150, 30, hWnd, (HMENU)108, NULL, NULL);
            ShowWindow(hBtnEditScheme, SW_HIDE);

            hWndScheme = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY,
                                      470, 10, 200, 25, hWnd, NULL, NULL, NULL);

            hTabControl = CreateWindow(WC_TABCONTROL, NULL, WS_VISIBLE | WS_CHILD,
                                       10, 50, 660, 440, hWnd, NULL, NULL, NULL);
            TCITEM tie = {0};
            tie.mask = TCIF_TEXT;
            tie.pszText = L"Текст";
            TabCtrl_InsertItem(hTabControl, 0, &tie);
            tie.pszText = L"Файл";
            TabCtrl_InsertItem(hTabControl, 1, &tie);

            hLabelTextInput = CreateWindow(L"STATIC", L"Исходный текст для расшифровки:",
                                           WS_VISIBLE | WS_CHILD, 40, 150, 300, 20, hWnd, NULL, NULL, NULL);
            hWndTextInput = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL,
                                         40, 170, 620, 100, hWnd, NULL, NULL, NULL);
            hBtnEncryptText = CreateWindow(L"BUTTON", L"Зашифровать текст", WS_VISIBLE | WS_CHILD,
                                           40, 280, 150, 30, hWnd, (HMENU)102, NULL, NULL);
            hBtnDecryptText = CreateWindow(L"BUTTON", L"Расшифровать текст", WS_VISIBLE | WS_CHILD,
                                           200, 280, 150, 30, hWnd, (HMENU)103, NULL, NULL);
            hLabelTextOutput = CreateWindow(L"STATIC", L"Результат:",
                                            WS_VISIBLE | WS_CHILD, 40, 320, 300, 20, hWnd, NULL, NULL, NULL);
            hWndTextOutput = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                                          40, 340, 620, 100, hWnd, NULL, NULL, NULL);

            hLabelInputFile = CreateWindow(L"STATIC", L"Входной файл:",
                                           WS_VISIBLE | WS_CHILD, 40, 150, 100, 20, hWnd, NULL, NULL, NULL);
            hWndInput = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER,
                                     140, 150, 400, 25, hWnd, NULL, NULL, NULL);
            hBtnBrowseInput = CreateWindow(L"BUTTON", L"Обзор...", WS_VISIBLE | WS_CHILD,
                                           550, 150, 80, 25, hWnd, (HMENU)104, NULL, NULL);

            hLabelOutputFile = CreateWindow(L"STATIC", L"Выходной файл:",
                                            WS_VISIBLE | WS_CHILD, 40, 190, 100, 20, hWnd, NULL, NULL, NULL);
            hWndOutput = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER,
                                      140, 190, 400, 25, hWnd, NULL, NULL, NULL);
            hBtnBrowseOutput = CreateWindow(L"BUTTON", L"Обзор...", WS_VISIBLE | WS_CHILD,
                                            550, 190, 80, 25, hWnd, (HMENU)105, NULL, NULL);

            hBtnEncryptFile = CreateWindow(L"BUTTON", L"Зашифровать файл", WS_VISIBLE | WS_CHILD,
                                           40, 230, 150, 30, hWnd, (HMENU)106, NULL, NULL);
            hBtnDecryptFile = CreateWindow(L"BUTTON", L"Расшифровать файл", WS_VISIBLE | WS_CHILD,
                                           200, 230, 150, 30, hWnd, (HMENU)107, NULL, NULL);

            SwitchTab(0);
            break;
        }
        case WM_SIZE: {
            RECT rc;
            GetClientRect(hWnd, &rc);
            ResizeControls(hWnd, rc.right - rc.left, rc.bottom - rc.top);
            break;
        }
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
                case 100: {
                    OPENFILENAME ofn = {0};
                    wchar_t file[260] = {0};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hWnd;
                    ofn.lpstrFile = file;
                    ofn.nMaxFile = 260;
                    ofn.lpstrFilter = L"Cipher Files\0*.cipher\0";
                    ofn.Flags = OFN_FILEMUSTEXIST;
                    if (GetOpenFileName(&ofn)) {
                        schemeFilePath = file;
                        SetWindowText(hWndScheme, schemeFilePath.c_str());
                        LoadScheme(schemeFilePath);
                    }
                    break;
                }
                case 101: {
                    HWND hCreate = CreateWindow(L"CreateSchemeClass", L"Создание схемы",
                                                WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_MINIMIZEBOX,
                                                100, 100, 420, 300,
                                                hWnd, NULL, GetModuleHandle(NULL), NULL);
                    HICON hIcon = CreateIconFromResourceEx((PBYTE)fallback_ico, sizeof(fallback_ico), TRUE, 0x00030000, 0, 0, LR_DEFAULTCOLOR);
                    if (hIcon) {
                        SendMessage(hCreate, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
                        SendMessage(hCreate, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
                    }
                    ShowWindow(hCreate, SW_SHOW);
                    UpdateWindow(hCreate);
                    MSG msg2;
                    while (IsWindow(hCreate) && GetMessage(&msg2, NULL, 0, 0)) {
                        TranslateMessage(&msg2);
                        DispatchMessage(&msg2);
                    }
                    break;
                }
                case 108: {
                    HWND hCreate = CreateWindow(L"CreateSchemeClass", L"Редактирование схемы",
                                                WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_MINIMIZEBOX,
                                                100, 100, 420, 300,
                                                hWnd, NULL, GetModuleHandle(NULL), (LPVOID)&currentScheme);
                    HICON hIcon = CreateIconFromResourceEx((PBYTE)fallback_ico, sizeof(fallback_ico), TRUE, 0x00030000, 0, 0, LR_DEFAULTCOLOR);
                    if (hIcon) {
                        SendMessage(hCreate, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
                        SendMessage(hCreate, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
                    }
                    ShowWindow(hCreate, SW_SHOW);
                    UpdateWindow(hCreate);
                    MSG msg2;
                    while (IsWindow(hCreate) && GetMessage(&msg2, NULL, 0, 0)) {
                        TranslateMessage(&msg2);
                        DispatchMessage(&msg2);
                    }
                    break;
                }
                case 102: EncryptText(); break;
                case 103: DecryptText(); break;
                case 104: {
                    OPENFILENAME ofn = {0};
                    wchar_t file[260] = {0};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hWnd;
                    ofn.lpstrFile = file;
                    ofn.nMaxFile = 260;
                    ofn.Flags = OFN_FILEMUSTEXIST;
                    if (GetOpenFileName(&ofn))
                        SetWindowText(hWndInput, file);
                    break;
                }
                case 105: {
                    OPENFILENAME ofn = {0};
                    wchar_t file[260] = {0};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hWnd;
                    ofn.lpstrFile = file;
                    ofn.nMaxFile = 260;
                    ofn.Flags = OFN_OVERWRITEPROMPT;
                    if (GetSaveFileName(&ofn))
                        SetWindowText(hWndOutput, file);
                    break;
                }
                case 106: EncryptFile(); break;
                case 107: DecryptFile(); break;
            }
            break;
        }
        case WM_NOTIFY: {
            if (((LPNMHDR)lParam)->code == TCN_SELCHANGE) {
                int idx = TabCtrl_GetCurSel(hTabControl);
                SwitchTab(idx);
            }
            break;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

void ResizeControls(HWND hWnd, int width, int height) {
    if (width < 500) width = 500;
    if (height < 400) height = 400;
    SetWindowPos(hWndScheme, NULL, 470, 10, width - 480, 25, SWP_NOZORDER);
    SetWindowPos(hBtnEditScheme, NULL, 310, 10, 150, 30, SWP_NOZORDER);
    int tabLeft = 10, tabTop = 50;
    int tabWidth = width - 20, tabHeight = height - 60;
    SetWindowPos(hTabControl, NULL, tabLeft, tabTop, tabWidth, tabHeight, SWP_NOZORDER);
    int xBase = 40;
    int fieldWidth = width - xBase - 60;
    if (fieldWidth < 200) fieldWidth = 200;
    SetWindowPos(hLabelTextInput, NULL, xBase, 150, 300, 20, SWP_NOZORDER);
    SetWindowPos(hWndTextInput, NULL, xBase, 170, fieldWidth, 100, SWP_NOZORDER);
    SetWindowPos(hBtnEncryptText, NULL, xBase, 280, 150, 30, SWP_NOZORDER);
    SetWindowPos(hBtnDecryptText, NULL, xBase + 160, 280, 150, 30, SWP_NOZORDER);
    SetWindowPos(hLabelTextOutput, NULL, xBase, 320, 300, 20, SWP_NOZORDER);
    SetWindowPos(hWndTextOutput, NULL, xBase, 340, fieldWidth, 100, SWP_NOZORDER);
    SetWindowPos(hLabelInputFile, NULL, xBase, 150, 100, 20, SWP_NOZORDER);
    SetWindowPos(hWndInput, NULL, xBase + 100, 150, fieldWidth - 180, 25, SWP_NOZORDER);
    SetWindowPos(hBtnBrowseInput, NULL, xBase + fieldWidth - 80, 150, 80, 25, SWP_NOZORDER);
    SetWindowPos(hLabelOutputFile, NULL, xBase, 190, 100, 20, SWP_NOZORDER);
    SetWindowPos(hWndOutput, NULL, xBase + 100, 190, fieldWidth - 180, 25, SWP_NOZORDER);
    SetWindowPos(hBtnBrowseOutput, NULL, xBase + fieldWidth - 80, 190, 80, 25, SWP_NOZORDER);
    SetWindowPos(hBtnEncryptFile, NULL, xBase, 230, 150, 30, SWP_NOZORDER);
    SetWindowPos(hBtnDecryptFile, NULL, xBase + 160, 230, 150, 30, SWP_NOZORDER);
}

LRESULT CALLBACK CreateSchemeWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static std::vector<std::pair<std::wstring, std::wstring>>* pSteps = nullptr;
    static HWND hName, hAlphabet, hDesc, hType, hParam, hList;
    static CipherScheme* pEditScheme = nullptr;
    switch (msg) {
        case WM_CREATE: {
            pSteps = new std::vector<std::pair<std::wstring, std::wstring>>();
            CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
            pEditScheme = (CipherScheme*)pCreate->lpCreateParams;

            CreateWindow(L"STATIC", L"Название:", WS_VISIBLE | WS_CHILD, 10, 10, 80, 20, hWnd, NULL, NULL, NULL);
            hName = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 90, 10, 200, 20, hWnd, (HMENU)100, NULL, NULL);
            CreateWindow(L"STATIC", L"Алфавит:", WS_VISIBLE | WS_CHILD, 10, 30, 80, 20, hWnd, NULL, NULL, NULL);
            hAlphabet = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 90, 30, 200, 20, hWnd, (HMENU)101, NULL, NULL);
            CreateWindow(L"STATIC", L"Описание:", WS_VISIBLE | WS_CHILD, 10, 50, 80, 20, hWnd, NULL, NULL, NULL);
            hDesc = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 90, 50, 200, 20, hWnd, (HMENU)102, NULL, NULL);
            CreateWindow(L"STATIC", L"Тип шага:", WS_VISIBLE | WS_CHILD, 10, 80, 80, 20, hWnd, NULL, NULL, NULL);
            hType = CreateWindow(L"COMBOBOX", NULL, WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL, 90, 80, 80, 100, hWnd, (HMENU)200, NULL, NULL);
            SendMessage(hType, CB_ADDSTRING, 0, (LPARAM)L"caesar");
            SendMessage(hType, CB_ADDSTRING, 0, (LPARAM)L"substitute");
            SendMessage(hType, CB_ADDSTRING, 0, (LPARAM)L"reverse");
            SendMessage(hType, CB_ADDSTRING, 0, (LPARAM)L"xor");
            SendMessage(hType, CB_ADDSTRING, 0, (LPARAM)L"transpose");
            SendMessage(hType, CB_ADDSTRING, 0, (LPARAM)L"vigenere");
            SendMessage(hType, CB_SETCURSEL, 0, 0);
            CreateWindow(L"STATIC", L"Параметры:", WS_VISIBLE | WS_CHILD, 10, 100, 80, 20, hWnd, NULL, NULL, NULL);
            hParam = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 90, 100, 80, 20, hWnd, (HMENU)210, NULL, NULL);
            CreateWindow(L"BUTTON", L"Добавить", WS_VISIBLE | WS_CHILD, 180, 80, 60, 25, hWnd, (HMENU)201, NULL, NULL);
            CreateWindow(L"BUTTON", L"Удалить", WS_VISIBLE | WS_CHILD, 250, 80, 60, 25, hWnd, (HMENU)202, NULL, NULL);
            hList = CreateWindow(L"LISTBOX", NULL, WS_VISIBLE | WS_CHILD | WS_VSCROLL | WS_BORDER, 10, 130, 380, 100, hWnd, (HMENU)300, NULL, NULL);
            CreateWindow(L"BUTTON", L"Сохранить", WS_VISIBLE | WS_CHILD, 140, 240, 80, 25, hWnd, (HMENU)IDOK, NULL, NULL);
            CreateWindow(L"BUTTON", L"Отмена", WS_VISIBLE | WS_CHILD, 230, 240, 80, 25, hWnd, (HMENU)IDCANCEL, NULL, NULL);

            if (pEditScheme) {
                SetWindowText(hName, utf8_to_wstring(pEditScheme->name).c_str());
                SetWindowText(hAlphabet, utf8_to_wstring(pEditScheme->originalAlphabet.empty() ? pEditScheme->alphabet : pEditScheme->originalAlphabet).c_str());
                SetWindowText(hDesc, utf8_to_wstring(pEditScheme->description).c_str());
                for (const auto& step : pEditScheme->steps) {
                    std::wstring type = utf8_to_wstring(step->type_name());
                    std::wstring params = utf8_to_wstring(step->serialize_params());
                    pSteps->push_back({type, params});
                    std::wstring display = type + (params.empty() ? L"" : L" " + params);
                    SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)display.c_str());
                }
            }
            SetWindowText(hParam, L"shift=");
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            if (id == IDOK) {
                wchar_t name[256], alph[256], desc[256];
                GetWindowText(hName, name, 256);
                GetWindowText(hAlphabet, alph, 256);
                GetWindowText(hDesc, desc, 256);

                CipherScheme scheme;
                scheme.name = wstring_to_utf8(name);
                scheme.originalAlphabet = wstring_to_utf8(alph);
                scheme.alphabet = ExpandAlphabet(scheme.originalAlphabet);
                scheme.description = wstring_to_utf8(desc);

                for (const auto& step : *pSteps) {
                    std::string type = wstring_to_utf8(step.first);
                    std::string paramStr = wstring_to_utf8(step.second);
                    std::map<std::string, std::string> params;
                    std::istringstream iss(paramStr);
                    std::string token;
                    while (iss >> token) {
                        size_t eq = token.find('=');
                        if (eq != std::string::npos) {
                            std::string key = token.substr(0, eq);
                            std::string value = token.substr(eq+1);
                            if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
                                value = value.substr(1, value.size()-2);
                            params[key] = value;
                        }
                    }
                    try {
                        scheme.steps.push_back(StepFactory::create(type, params, scheme.alphabet));
                    } catch (...) {
                        MessageBox(hWnd, L"Ошибка в параметрах шага.\n\nФормат параметров:\n  caesar: shift=3\n  substitute: map=A->B,C->D\n  reverse: (без параметров)\n  xor: key=secret\n  transpose: keyword=SECRET\n  vigenere: key=SECRET\n\nТекст сообщения можно выделить и скопировать (Ctrl+C).", L"Ошибка", MB_ICONINFORMATION);
                        return TRUE;
                    }
                }

                if (pEditScheme) {
                    *pEditScheme = std::move(scheme);
                    SaveScheme(schemeFilePath, *pEditScheme);
                    LoadScheme(schemeFilePath);
                } else {
                    OPENFILENAME ofn = {0};
                    wchar_t file[260] = L"";
                    std::wstring defaultName = utf8_to_wstring(scheme.name) + L".cipher";
                    wcsncpy_s(file, defaultName.c_str(), 260);
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hWnd;
                    ofn.lpstrFile = file;
                    ofn.nMaxFile = 260;
                    ofn.lpstrFilter = L"Cipher Files\0*.cipher\0";
                    ofn.Flags = OFN_OVERWRITEPROMPT;
                    if (GetSaveFileName(&ofn)) {
                        std::wstring chosen(file);
                        EnsureCipherExt(chosen);
                        SaveScheme(chosen, scheme);
                        schemeFilePath = chosen;
                        SetWindowText(hWndScheme, schemeFilePath.c_str());
                        LoadScheme(schemeFilePath);
                    }
                }
                delete pSteps;
                DestroyWindow(hWnd);
                return TRUE;
            }
            if (id == IDCANCEL) { delete pSteps; DestroyWindow(hWnd); return TRUE; }
            if (id == 201) {
                wchar_t typeBuf[64], paramBuf[512];
                GetWindowText(hType, typeBuf, 64);
                GetWindowText(hParam, paramBuf, 512);
                std::wstring type(typeBuf);
                std::wstring param(paramBuf);
                if ((type == L"caesar" || type == L"substitute" || type == L"xor" || type == L"vigenere" || type == L"transpose") && param.empty()) {
                    MessageBox(hWnd, L"Для этого шага необходимо заполнить параметры.", L"Ошибка", MB_ICONWARNING);
                    return TRUE;
                }
                pSteps->push_back({type, param});
                std::wstring display = type + (param.empty() ? L"" : L" " + param);
                SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)display.c_str());
                return TRUE;
            }
            if (id == 202) {
                int sel = SendMessage(hList, LB_GETCURSEL, 0, 0);
                if (sel != LB_ERR) { SendMessage(hList, LB_DELETESTRING, sel, 0); pSteps->erase(pSteps->begin() + sel); }
                return TRUE;
            }
            if (id == 200 && HIWORD(wParam) == CBN_SELCHANGE) {
                int sel = SendMessage(hType, CB_GETCURSEL, 0, 0);
                if (sel != CB_ERR) {
                    wchar_t typeBuf[64];
                    SendMessage(hType, CB_GETLBTEXT, sel, (LPARAM)typeBuf);
                    std::wstring type(typeBuf);
                    if (type == L"caesar") SetWindowText(hParam, L"shift=");
                    else if (type == L"substitute") SetWindowText(hParam, L"map=");
                    else if (type == L"xor" || type == L"vigenere") SetWindowText(hParam, L"key=");
                    else if (type == L"transpose") SetWindowText(hParam, L"keyword=");
                    else if (type == L"reverse") SetWindowText(hParam, L"");
                }
                return TRUE;
            }
            break;
        }
        case WM_CLOSE: { delete pSteps; DestroyWindow(hWnd); return TRUE; }
        case WM_DESTROY: return TRUE;
        default: return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return TRUE;
}

void EnsureCipherExt(std::wstring& filePath) {
    if (filePath.size() < 7 || filePath.substr(filePath.size() - 7) != L".cipher") filePath += L".cipher";
}

void SwitchTab(int index) {
    BOOL isText = (index == 0);
    ShowWindow(hLabelTextInput, isText); ShowWindow(hWndTextInput, isText);
    ShowWindow(hBtnEncryptText, isText); ShowWindow(hBtnDecryptText, isText);
    ShowWindow(hLabelTextOutput, isText); ShowWindow(hWndTextOutput, isText);
    ShowWindow(hLabelInputFile, !isText); ShowWindow(hWndInput, !isText);
    ShowWindow(hBtnBrowseInput, !isText); ShowWindow(hLabelOutputFile, !isText);
    ShowWindow(hWndOutput, !isText); ShowWindow(hBtnBrowseOutput, !isText);
    ShowWindow(hBtnEncryptFile, !isText); ShowWindow(hBtnDecryptFile, !isText);
}

void LoadScheme(const std::wstring& path) {
    std::filesystem::path filePath(path);
    std::ifstream in(filePath);
    if (!in) {
        MessageBox(NULL, L"Не удалось открыть файл схемы", L"Ошибка", MB_ICONERROR);
        ShowWindow(hBtnEditScheme, SW_HIDE);
        return;
    }
    std::stringstream buf;
    buf << in.rdbuf();
    try {
        currentScheme = CipherScheme::deserialize(buf.str());

        std::string alph = currentScheme.originalAlphabet.empty()
                               ? currentScheme.alphabet
                               : currentScheme.originalAlphabet;
        currentScheme.alphabet = ExpandAlphabet(alph);

        ShowWindow(hBtnEditScheme, SW_SHOW);
        if (currentScheme.steps.empty())
            MessageBox(NULL, L"Схема загружена, но в ней нет шагов", L"Предупреждение", MB_ICONWARNING);
    } catch (const std::exception& e) {
        std::string errMsg = "Ошибка парсинга схемы: " + std::string(e.what());
        MessageBox(NULL, utf8_to_wstring(errMsg).c_str(), L"Ошибка", MB_ICONERROR);
        currentScheme = CipherScheme();
        ShowWindow(hBtnEditScheme, SW_HIDE);
    }
}

void SaveScheme(const std::wstring& path, const CipherScheme& scheme) {
    std::filesystem::path filePath(path);
    std::ofstream out(filePath);
    if (!out) { MessageBox(NULL, L"Не удалось сохранить файл", L"Ошибка", MB_ICONERROR); return; }
    out << scheme.serialize();
}

void EncryptFile() {
    if (currentScheme.steps.empty()) { MessageBox(NULL, L"Сначала откройте корректную схему шифрования", L"Ошибка", MB_ICONERROR); return; }
    wchar_t inFile[260], outFile[260];
    GetWindowText(hWndInput, inFile, 260); GetWindowText(hWndOutput, outFile, 260);
    std::filesystem::path inPath(inFile), outPath(outFile);
    std::ifstream in(inPath, std::ios::binary); std::ofstream out(outPath, std::ios::binary);
    if (!in || !out) { MessageBox(NULL, L"Не удалось открыть входной или выходной файл", L"Ошибка", MB_ICONERROR); return; }
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CipherEngine engine(currentScheme);
    std::string enc = engine.encrypt(data);
    out.write(enc.data(), enc.size());
    MessageBox(NULL, L"Файл зашифрован!", L"Готово", MB_OK);
}

void DecryptFile() {
    if (currentScheme.steps.empty()) { MessageBox(NULL, L"Сначала откройте корректную схему шифрования", L"Ошибка", MB_ICONERROR); return; }
    wchar_t inFile[260], outFile[260];
    GetWindowText(hWndInput, inFile, 260); GetWindowText(hWndOutput, outFile, 260);
    std::filesystem::path inPath(inFile), outPath(outFile);
    std::ifstream in(inPath, std::ios::binary); std::ofstream out(outPath, std::ios::binary);
    if (!in || !out) { MessageBox(NULL, L"Не удалось открыть входной или выходной файл", L"Ошибка", MB_ICONERROR); return; }
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CipherEngine engine(currentScheme);
    std::string dec = engine.decrypt(data);
    out.write(dec.data(), dec.size());
    MessageBox(NULL, L"Файл расшифрован!", L"Готово", MB_OK);
}

void EncryptText() {
    if (currentScheme.steps.empty()) { MessageBox(NULL, L"Сначала откройте корректную схему шифрования", L"Ошибка", MB_ICONERROR); return; }
    int len = GetWindowTextLength(hWndTextInput);
    if (len == 0) return;
    wchar_t* buf = new wchar_t[len+1];
    GetWindowText(hWndTextInput, buf, len+1);
    std::string text = wstring_to_utf8(buf);
    delete[] buf;
    CipherEngine engine(currentScheme);
    std::string encrypted = engine.encrypt(text);
    if (currentScheme.alphabet.empty()) {
        static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string b64; int val = 0, valb = -6;
        for (unsigned char c : encrypted) {
            val = (val << 8) + c; valb += 8;
            while (valb >= 0) { b64.push_back(chars[(val >> valb) & 0x3F]); valb -= 6; }
        }
        if (valb > -6) b64.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (b64.size() % 4) b64.push_back('=');
        SetWindowText(hWndTextOutput, utf8_to_wstring(b64).c_str());
    } else {
        SetWindowText(hWndTextOutput, utf8_to_wstring(encrypted).c_str());
    }
}

void DecryptText() {
    if (currentScheme.steps.empty()) { MessageBox(NULL, L"Сначала откройте корректную схему шифрования", L"Ошибка", MB_ICONERROR); return; }
    int len = GetWindowTextLength(hWndTextInput);
    if (len == 0) return;
    wchar_t* buf = new wchar_t[len+1];
    GetWindowText(hWndTextInput, buf, len+1);
    std::wstring inputW(buf);
    delete[] buf;
    if (currentScheme.alphabet.empty()) {
        std::string b64 = wstring_to_utf8(inputW);
        std::string encrypted;
        static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int val = 0, valb = -8;
        for (char c : b64) {
            if (c == '=') break;
            auto p = strchr(chars, c); if (!p) continue;
            val = (val << 6) + (p - chars); valb += 6;
            if (valb >= 0) { encrypted.push_back((val >> valb) & 0xFF); valb -= 8; }
        }
        CipherEngine engine(currentScheme);
        std::string decrypted = engine.decrypt(encrypted);
        SetWindowText(hWndTextOutput, utf8_to_wstring(decrypted).c_str());
    } else {
        std::string encrypted = wstring_to_utf8(inputW);
        CipherEngine engine(currentScheme);
        std::string decrypted = engine.decrypt(encrypted);
        SetWindowText(hWndTextOutput, utf8_to_wstring(decrypted).c_str());
    }
}