// SPDX-License-Identifier: GPL-3.0-only
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <vector>
#pragma comment(lib,"ws2_32.lib")

// '1' records a policy denial or an unanswered connection to the live control listener.
// '0' means connected; '?' separates setup and unrelated socket errors from denials.
static char checkBlocked(const std::wstring& ip, unsigned short port, int family, long seconds = 2) {
    sockaddr_storage address{};
    void* binary;
    int length;
    if (family == AF_INET) {
        auto& v4 = reinterpret_cast<sockaddr_in&>(address);
        v4.sin_family = AF_INET; v4.sin_port = htons(port);
        binary = &v4.sin_addr; length = sizeof(v4);
    } else {
        auto& v6 = reinterpret_cast<sockaddr_in6&>(address);
        v6.sin6_family = AF_INET6; v6.sin6_port = htons(port);
        binary = &v6.sin6_addr; length = sizeof(v6);
    }
    if (InetPtonW(family, ip.c_str(), binary) != 1) return '?';
    SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return WSAGetLastError() == WSAEACCES ? '1' : '?';
    char result = '?';
    u_long nonblocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonblocking) == 0) {
        int error = connect(s, reinterpret_cast<sockaddr*>(&address), length) == 0 ? 0 : WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            fd_set ready, failed;
            FD_ZERO(&ready); FD_ZERO(&failed); FD_SET(s, &ready); FD_SET(s, &failed);
            timeval deadline{seconds, 0};
            const int event = select(0, nullptr, &ready, &failed, &deadline);
            if (event == 0) error = WSAETIMEDOUT;
            if (event > 0) {
                int size = sizeof(error);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) != 0) error = -1;
            }
        }
        if (error == 0) result = '0';
        if (error == WSAEACCES || error == WSAETIMEDOUT) result = '1';
    }
    closesocket(s);
    return result;
}

static bool readBytes(const std::wstring& path, std::string& output, DWORD& error) {
    HANDLE h=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
    if(h==INVALID_HANDLE_VALUE){error=GetLastError();return false;}
    char buffer[8192]; DWORD n=0;
    bool ok=ReadFile(h,buffer,sizeof(buffer),&n,nullptr)!=FALSE;
    error=ok?0:GetLastError();CloseHandle(h);if(ok) output.assign(buffer,n);return ok;
}
static bool writeBytes(const std::wstring& path,const std::string& text,DWORD& error) {
    HANDLE h=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_ALWAYS,0,nullptr);
    if(h==INVALID_HANDLE_VALUE){error=GetLastError();return false;}
    DWORD n=0;bool ok=WriteFile(h,text.data(),static_cast<DWORD>(text.size()),&n,nullptr)!=FALSE && n==text.size();
    error=ok?0:GetLastError();CloseHandle(h);return ok;
}
static void stage(const char* name,DWORD code=0) {
    DWORD ignored=0;
    writeBytes(L"fixture-stage.txt",std::string(name)+":"+std::to_string(code),ignored);
}
constexpr int textEditId = 101;
static std::wstring expectedText;
static LRESULT CALLBACK windowProc(HWND h,UINT m,WPARAM w,LPARAM l) {
    if (m == WM_SETFOCUS) {
        HWND edit = GetDlgItem(h, textEditId);
        if (edit) SetFocus(edit);
    }
    if (m == WM_COMMAND && LOWORD(w) == textEditId && HIWORD(w) == EN_CHANGE && !expectedText.empty()) {
        wchar_t actual[128]{};
        HWND edit = GetDlgItem(h, textEditId);
        if (edit && edit == reinterpret_cast<HWND>(l)) {
            int length = GetWindowTextW(edit, actual, 128);
            DWORD ignored = 0;
            writeBytes(L"fixture-text-receipt.txt",
                length > 0 && std::wstring(actual, length) == expectedText ? "1" : "0", ignored);
        }
    }
    if(m==WM_TIMER||m==WM_CLOSE){DestroyWindow(h);return 0;}
    if(m==WM_DESTROY){PostQuitMessage(0);return 0;}return DefWindowProcW(h,m,w,l);
}
int WINAPI wWinMain(HINSTANCE inst,HINSTANCE,wchar_t* args,int) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    if (GetFileAttributesW(L"fixture-exit.test") != INVALID_FILE_ATTRIBUTES) return 32;
    stage("entered");
    std::string bytes;DWORD e=0;
    if(!readBytes(L"fixture.txt",bytes,e)||bytes.size()%2){stage("read-config",e);return 20;}
    std::wstring lines(bytes.size()/2,L'\0');CopyMemory(lines.data(),bytes.data(),bytes.size());
    std::vector<std::wstring> paths;
    size_t last=0;
    for(size_t i=0;i<lines.size();i++) if(lines[i]==L'\n'){paths.push_back(lines.substr(last,i-last));last=i+1;}
    if(paths.size()!=6 && paths.size()!=7){stage("parse-config");return 21;}
    if (GetFileAttributesW(L"fixture-handoff.test") != INVALID_FILE_ATTRIBUTES && wcscmp(args, L"--fixture-worker") != 0) {
        // Only the synthetic fixture has this handoff mode. The helper is a
        // differently named copy in its granted, read-only test directory.
        auto slash = paths[1].find_last_of(L'\\');
        if (slash == std::wstring::npos) return 26;
        std::wstring worker = paths[1].substr(0, slash + 1) + L"AppShieldFixtureChild.exe";
        std::wstring command = L"\"" + worker + L"\" --fixture-worker";
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(worker.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
            nullptr, nullptr, &startup, &process)) {
            stage("spawn-worker", GetLastError());
            return 27;
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return GetFileAttributesW(L"fixture-nonzero-handoff.test") != INVALID_FILE_ATTRIBUTES ? 33 : 0;
    }
    bool priv=!readBytes(paths[0],bytes,e) && e==ERROR_ACCESS_DENIED;
    bool ro=readBytes(paths[1],bytes,e) && bytes=="allowed";
    bool denied=!writeBytes(paths[1],"changed",e) && e==ERROR_ACCESS_DENIED;
    bool rw=writeBytes(paths[2],"approved",e);
    std::string facts=std::string(priv?"1":"0")+(ro?"1":"0")+(denied?"1":"0")+(rw?"1":"0");
    WSADATA data{};
    stage("network");
    int startup=WSAStartup(MAKEWORD(2,2),&data);
    if(startup!=0){stage("winsock",static_cast<DWORD>(startup));return 25;}
    auto port=static_cast<unsigned short>(std::stoul(paths[4]));
    facts+=checkBlocked(L"127.0.0.1",port,AF_INET);
    facts+=checkBlocked(paths[3],port,AF_INET);
    facts+=checkBlocked(L"::1",static_cast<unsigned short>(std::stoul(paths[5])),AF_INET6);
    if (paths.size()==7) {
        stage("public-connect");
        facts+=checkBlocked(paths[6],443,AF_INET,5);
    }
    WSACleanup();
    if(!writeBytes(L"fixture-result.txt",facts,e)){stage("write-result",e);return 22;}
    WNDCLASSW wc{};wc.lpfnWndProc=windowProc;wc.hInstance=inst;wc.lpszClassName=L"AppShieldFixture";
    if(!RegisterClassW(&wc)){stage("window-class",GetLastError());return 23;}
    std::string nonce;
    bool pasteTrial=readBytes(L"fixture-text-nonce.txt",nonce,e) && nonce.size()==32
        && nonce.find_first_not_of("0123456789abcdef")==std::string::npos;
    if (pasteTrial) expectedText=L"AppShield \u6587\u672c " + std::wstring(nonce.begin(),nonce.end());
    HWND h=CreateWindowExW(pasteTrial?0:WS_EX_NOACTIVATE,wc.lpszClassName,L"AppShield synthetic test",WS_OVERLAPPEDWINDOW,0,0,230,96,nullptr,nullptr,inst,nullptr);
    if(!h){stage("window-create",GetLastError());return 24;}
    if (pasteTrial) {
        HWND edit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
            6,6,190,28,h,reinterpret_cast<HMENU>(static_cast<INT_PTR>(textEditId)),inst,nullptr);
        if(!edit){stage("edit-create",GetLastError());return 28;}
        ShowWindow(h,SW_SHOWNORMAL);
        SetFocus(edit);
    } else ShowWindow(h,SW_SHOWNOACTIVATE);
    SetTimer(h,1,60000,nullptr);
    stage("window-ready");
    MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    return 0;
}
