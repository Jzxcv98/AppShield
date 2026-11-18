// SPDX-License-Identifier: GPL-3.0-only
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>

#include <cstdio>
#include <cwchar>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

namespace {
constexpr char privateMarker[] = "APPSHIELD_PRIVATE";
constexpr char sharedMarker[] = "APPSHIELD_SHARED";

enum class ReadResult { match, denied, other };

ReadResult readMarker(const std::wstring& path, const char* marker) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_ACCESS_DENIED ? ReadResult::denied : ReadResult::other;

    char buffer[64];
    DWORD count = 0;
    BOOL ok = ReadFile(file, buffer, sizeof(buffer), &count, nullptr);
    CloseHandle(file);
    return ok && count == std::strlen(marker) && std::memcmp(buffer, marker, count) == 0
               ? ReadResult::match : ReadResult::other;
}

bool hasAppContainerSid(PSID expected) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD length = 0, isAppContainer = 0;
    bool match = false;
    if (GetTokenInformation(token, TokenIsAppContainer, &isAppContainer,
                            sizeof(isAppContainer), &length) && isAppContainer) {
        GetTokenInformation(token, TokenAppContainerSid, nullptr, 0, &length);
        std::vector<BYTE> storage(length);
        if (length && GetTokenInformation(token, TokenAppContainerSid, storage.data(), length, &length)) {
            PSID actual = reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(storage.data())->TokenAppContainer;
            match = actual && EqualSid(actual, expected);
        }
    }
    CloseHandle(token);
    return match;
}

int runChild(const std::wstring& root, PSID sid, bool granted) {
    if (!hasAppContainerSid(sid)) return 21;
    if (readMarker(root + L"\\private.txt", privateMarker) != ReadResult::denied) return 22;
    ReadResult expected = granted ? ReadResult::match : ReadResult::denied;
    if (readMarker(root + L"\\shared.txt", sharedMarker) != expected) return 23;
    return 0;
}

int launch(const std::wstring& root, const std::wstring& name, PSID sid, bool granted) {
    if (readMarker(root + L"\\private.txt", privateMarker) != ReadResult::match ||
        readMarker(root + L"\\shared.txt", sharedMarker) != ReadResult::match) {
        std::fputs("FAIL host read baseline\n", stderr);
        return 1;
    }
    std::puts("PASS host read both synthetic markers");
    std::fflush(stdout);

    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<BYTE> memory(bytes);
    auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(memory.data());
    if (!bytes || !InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) {
        std::fprintf(stderr, "FAIL initialize process attributes (Win32 %lu)\n", GetLastError());
        return 1;
    }

    SECURITY_CAPABILITIES capabilities{};
    capabilities.AppContainerSid = sid;
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION child{};
    std::wstring exe = root + L"\\file-probe.exe";
    std::wstring mode = granted ? L"--child-granted" : L"--child-blocked";
    std::wstring cmd = L"\"" + exe + L"\" " + mode + L" \"" + name + L"\" \"" + root + L"\"";
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                   &capabilities, sizeof(capabilities), nullptr, nullptr)) {
        std::fprintf(stderr, "FAIL attach security capabilities (Win32 %lu)\n", GetLastError());
        DeleteProcThreadAttributeList(attributes);
        return 1;
    }
    BOOL started = CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE,
                                  EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr,
                                  root.c_str(), &startup.StartupInfo, &child);
    DWORD launchError = started ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(attributes);
    if (!started) {
        std::fprintf(stderr, "FAIL CreateProcessW AppContainer (Win32 %lu)\n", launchError);
        return 1;
    }
    CloseHandle(child.hThread);
    DWORD code = 0;
    if (WaitForSingleObject(child.hProcess, 15000) != WAIT_OBJECT_0) {
        TerminateProcess(child.hProcess, 24);
        WaitForSingleObject(child.hProcess, 5000);
        code = 24;
    } else if (!GetExitCodeProcess(child.hProcess, &code)) {
        code = 25;
    }
    CloseHandle(child.hProcess);
    if (code != 0) {
        std::fprintf(stderr, "FAIL child status %lu (21 token, 22 private read, 23 shared read, 24 timeout)\n", code);
        return 1;
    }
    std::puts("PASS child token matched the requested AppContainer SID");
    std::puts("PASS private read returned access denied");
    std::puts(granted ? "PASS explicitly granted read returned the shared marker"
                      : "PASS shared read returned access denied before grant");
    return 0;
}

bool grantSharedRead(const std::wstring& root, PSID sid) {
    std::wstring file = root + L"\\shared.txt";
    PACL current = nullptr, updated = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD status = GetNamedSecurityInfoW(file.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                         nullptr, nullptr, &current, nullptr, &descriptor);
    if (status == ERROR_SUCCESS) {
        EXPLICIT_ACCESSW access{};
        access.grfAccessMode = GRANT_ACCESS;
        access.grfAccessPermissions = FILE_GENERIC_READ;
        BuildTrusteeWithSidW(&access.Trustee, sid);
        status = current ? SetEntriesInAclW(1, &access, current, &updated) : ERROR_INVALID_ACL;
    }
    if (status == ERROR_SUCCESS) {
        status = SetNamedSecurityInfoW(file.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, updated, nullptr);
    }
    LocalFree(updated);
    LocalFree(descriptor);
    if (status != ERROR_SUCCESS) std::fprintf(stderr, "FAIL grant shared read (Win32 %lu)\n", status);
    return status == ERROR_SUCCESS;
}

int withTemporaryProfile(const std::wstring& name, const std::wstring& root) {
    const std::wstring prefix = L"AppShield.FileProbe.";
    if (name.size() != prefix.size() + 32 || name.compare(0, prefix.size(), prefix) != 0 ||
        name.find_first_not_of(L"0123456789abcdef", prefix.size()) != std::wstring::npos) return 2;

    PSID profileSid = nullptr;
    HRESULT status = CreateAppContainerProfile(name.c_str(), L"AppShield file probe",
                                               L"Temporary synthetic file check", nullptr, 0, &profileSid);
    if (status != S_OK) {
        // An existing profile belongs to another run. Never reuse or delete it.
        std::fprintf(stderr, "FAIL create temporary profile (HRESULT 0x%08lx)\n", static_cast<unsigned long>(status));
        return 1;
    }
    int result = 1;
    try {
        if (launch(root, name, profileSid, false) == 0 && grantSharedRead(root, profileSid)) {
            result = launch(root, name, profileSid, true);
        }
    } catch (...) {
        std::fputs("FAIL unexpected probe exception\n", stderr);
    }
    FreeSid(profileSid);
    status = DeleteAppContainerProfile(name.c_str());
    if (status != S_OK) {
        std::fprintf(stderr, "FAIL delete temporary profile %ls (HRESULT 0x%08lx)\n",
                     name.c_str(), static_cast<unsigned long>(status));
        return 1;
    }
    std::puts("PASS temporary AppContainer profile removed");
    return result;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 3 && argc != 4) return 2;
    std::wstring mode = argv[1];
    if (mode == L"--run" && argc == 4) return withTemporaryProfile(argv[2], argv[3]);
    PSID sid = nullptr;
    // Deriving a SID does not create a persistent AppContainer profile.
    HRESULT result = DeriveAppContainerSidFromAppContainerName(argv[2], &sid);
    if (FAILED(result)) {
        std::fprintf(stderr, "FAIL derive SID (HRESULT 0x%08lx)\n", static_cast<unsigned long>(result));
        return 1;
    }
    int code = 2;
    if (mode == L"--sid" && argc == 3) {
        LPWSTR text = nullptr;
        if (ConvertSidToStringSidW(sid, &text)) {
            std::wprintf(L"%ls\n", text);
            LocalFree(text);
            code = 0;
        }
    } else if (argc == 4 && (mode == L"--child-granted" || mode == L"--child-blocked")) {
        code = runChild(argv[3], sid, mode == L"--child-granted");
    }
    FreeSid(sid);
    return code;
}
