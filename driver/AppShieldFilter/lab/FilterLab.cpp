// SPDX-License-Identifier: GPL-3.0-only
// Laboratory controller: it can launch only this executable's synthetic test.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <fltuser.h>
#include <objbase.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include "../PathPolicy.h"

#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

namespace {
struct Error { const char *stage; DWORD status; };
void need(bool ok, const char *stage) {
    if (!ok) throw Error{stage, GetLastError()};
}
void expect(bool ok, const char *stage) {
    if (!ok) throw Error{stage, ERROR_INVALID_DATA};
}
int policyChecks() {
    const auto rule = [](const wchar_t *p, ULONG rights) {
        ASF_RULE r{};
        r.Access = rights;
        r.Chars = static_cast<ULONG>(wcslen(p));
        wcscpy_s(r.Path, p);
        return r;
    };
    const auto read = ASF_READ, write = ASF_READ | ASF_WRITE;
    ASF_RULE roots[] = { rule(L"\\Device\\HarddiskVolume3\\Share", write),
        rule(L"\\Device\\HarddiskVolume3\\Share\\Reports", read),
        rule(L"\\Device\\HarddiskVolume3\\Share\\Reports", write) };
    const auto grant = [&](const wchar_t *n) {
        return AsfGrantForName(roots, 3, n, static_cast<ULONG>(wcslen(n)));
    };
    for (const auto& r : roots) expect(AsfValidRoot(&r), "admit normalized NT grant");
    expect(grant(roots[0].Path) == write, "whole directory");
    expect(grant(L"\\Device\\HarddiskVolume3\\Share\\report.txt") == write, "authorized subtree");
    expect(grant(L"\\Device\\HarddiskVolume3\\Share\\Reports\\a.txt") == read, "narrower read-only and duplicate intersection");
    expect(grant(L"\\Device\\HarddiskVolume3\\Shared\\x") == 0, "same-prefix sibling");
    expect(grant(L"\\Device\\HarddiskVolume3\\share\\x") == 0, "case-sensitive spelling");
    expect(grant(L"\\Device\\HarddiskVolume4\\Share\\x") == 0, "different volume");
    for (const wchar_t *s : {L"C:\\Share", L"\\Device\\Mup\\Share", L"\\Device\\HarddiskVolume3\\",
                             L"\\Device\\HarddiskVolume3\\a\\..\\b", L"\\Device\\HarddiskVolume3\\a:stream",
                             L"\\Device\\HarddiskVolume3\\double\\\\part", L"\\Device\\HarddiskVolume3\\wild*"}) {
        auto invalid = rule(s, read);
        expect(!AsfValidRoot(&invalid), "reject ambiguous or non-local grant");
    }
    auto malformed = roots[0]; malformed.Chars = ASF_PATH_CHARS;
    expect(!AsfValidRoot(&malformed), "reject invalid wire length");
    malformed = roots[0]; malformed.Access = ASF_WRITE;
    expect(!AsfValidRoot(&malformed), "reject unsupported rights");
    expect(AsfAllowsOpen(FILE_OPEN << 24, FALSE), "simple open existing");
    for (ULONG disposition : {FILE_SUPERSEDE, FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF})
        expect(!AsfAllowsOpen(disposition << 24, FALSE), "reject operations that can mutate before post-create");
    for (ULONG flags : {FILE_DELETE_ON_CLOSE, FILE_OPEN_BY_FILE_ID, FILE_OPEN_REPARSE_POINT, FILE_OPEN_FOR_BACKUP_INTENT})
        expect(!AsfAllowsOpen((FILE_OPEN << 24) | flags, FALSE), "reject ambiguous open modes");
    expect(!AsfAllowsOpen(FILE_OPEN << 24, TRUE), "deny target-directory opens");
    expect(AsfAllowsFinalObject(FILE_ATTRIBUTE_NORMAL, FALSE, 1, FALSE), "single ordinary file");
    expect(!AsfAllowsFinalObject(FILE_ATTRIBUTE_REPARSE_POINT, FALSE, 1, FALSE) &&
           !AsfAllowsFinalObject(FILE_ATTRIBUTE_REPARSE_POINT, TRUE, 1, FALSE), "reject redirected final objects");
    expect(!AsfAllowsFinalObject(FILE_ATTRIBUTE_NORMAL, FALSE, 2, FALSE) &&
           !AsfAllowsFinalObject(FILE_ATTRIBUTE_NORMAL, FALSE, 1, TRUE), "reject multiply linked or disappearing file");
    std::puts("PASS offline root grammar, component boundary, case, volume, overlapping rights, dispositions, file-ID, reparse and hardlink gates");
    return 0;
}
struct Handle {
    HANDLE h = nullptr;
    Handle() = default;
    explicit Handle(HANDLE value) : h(value) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { close(); }
    void close() {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = nullptr;
    }
};
struct FixtureIdentity {
    explicit FixtureIdentity(HANDLE ordinaryToken) {
        need(ImpersonateLoggedOnUser(ordinaryToken) != 0, "use ordinary identity for fixture storage");
    }
    ~FixtureIdentity() {
        if (!RevertToSelf()) TerminateProcess(GetCurrentProcess(), ERROR_CANNOT_IMPERSONATE);
    }
    FixtureIdentity(const FixtureIdentity&) = delete;
    FixtureIdentity& operator=(const FixtureIdentity&) = delete;
};
std::wstring modulePath() {
    std::vector<wchar_t> buf(32768);
    DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    need(n > 0 && n < buf.size(), "get test image path");
    return {buf.data(), n};
}
std::wstring windowsDir() {
    wchar_t path[MAX_PATH];
    UINT n = GetWindowsDirectoryW(path, MAX_PATH);
    need(n > 0 && n < MAX_PATH, "get Windows directory");
    return path;
}
std::wstring tempDir() {
    wchar_t path[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, path);
    need(n > 0 && n < MAX_PATH, "get temporary directory");
    return path;
}
std::wstring uniqueRoot() {
    GUID guid{};
    wchar_t label[40]{};
    expect(SUCCEEDED(CoCreateGuid(&guid)) && StringFromGUID2(guid, label, 40), "create fixture id");
    return tempDir() + L"AppShieldFilterLab." + label;
}
void createMarker(const std::wstring& path, const char *marker) {
    Handle h(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    need(h.h != INVALID_HANDLE_VALUE, "create synthetic marker");
    DWORD bytes;
    if (!WriteFile(h.h, marker, static_cast<DWORD>(strlen(marker)), &bytes, nullptr) || bytes != strlen(marker)) {
        DWORD error = GetLastError();
        h.close();
        DeleteFileW(path.c_str());
        throw Error{"write synthetic marker", error};
    }
}
void readMarker(const std::wstring& path, const char *marker) {
    Handle h(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    need(h.h != INVALID_HANDLE_VALUE, "open allowed synthetic marker");
    char buffer[32];
    DWORD n;
    need(ReadFile(h.h, buffer, sizeof(buffer), &n, nullptr), "read allowed marker");
    expect(n == strlen(marker) && !memcmp(buffer, marker, n), "verify marker contents");
}
void denyOpen(const std::wstring& path, DWORD access) {
    Handle h(CreateFileW(path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    DWORD status = GetLastError();
    expect(h.h == INVALID_HANDLE_VALUE && status == ERROR_ACCESS_DENIED, "expected precise access denial");
}
void overwriteExisting(const std::wstring& path, const char *value) {
    Handle output(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    need(output.h != INVALID_HANDLE_VALUE, "open writable synthetic fixture");
    DWORD written = 0;
    need(WriteFile(output.h, value, static_cast<DWORD>(strlen(value)), &written, nullptr) &&
         written == strlen(value), "write permitted marker");
}
void waitRelease(const std::wstring& path) {
    for (unsigned i = 0; i < 150; ++i) {
        Handle h(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        need(h.h != INVALID_HANDLE_VALUE, "open parent-exit checkpoint");
        char marker = 0;
        DWORD n = 0;
        need(ReadFile(h.h, &marker, 1, &n, nullptr) && n == 1, "read parent-exit checkpoint");
        if (marker == '1') return;
        Sleep(100);
    }
    throw Error{"parent-exit checkpoint timed out", WAIT_TIMEOUT};
}
ASF_RULE rootRule(const std::wstring& path, ULONG access) {
    Handle dir(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    need(dir.h != INVALID_HANDLE_VALUE, "open grant directory");
    ASF_RULE rule{};
    rule.Chars = GetFinalPathNameByHandleW(dir.h, rule.Path, ASF_PATH_CHARS,
                                          VOLUME_NAME_NT | FILE_NAME_NORMALIZED);
    need(rule.Chars > 0 && rule.Chars < ASF_PATH_CHARS, "get canonical NT grant");
    rule.Access = access;
    return rule;
}
void connect(Handle& port) {
    HRESULT hr = FilterConnectCommunicationPort(ASF_PORT_NAME, 0, nullptr, 0, nullptr, &port.h);
    if (FAILED(hr)) throw Error{"connect to AppShieldFilter (requires a loaded filter and authorized broker)", static_cast<DWORD>(hr)};
}
ASF_REPLY request(HANDLE port, ULONG op, HANDLE proc, const std::vector<ASF_RULE>& rules = {}) {
    ASF_REQUEST h{ASF_PROTOCOL, op, reinterpret_cast<ULONG_PTR>(proc), static_cast<ULONG>(rules.size()), 0};
    std::vector<BYTE> wire(sizeof(h) + rules.size() * sizeof(ASF_RULE));
    memcpy(wire.data(), &h, sizeof(h));
    if (!rules.empty()) memcpy(wire.data() + sizeof(h), rules.data(), rules.size() * sizeof(ASF_RULE));
    ASF_REPLY out{};
    DWORD n = 0;
    HRESULT hr = FilterSendMessage(port, wire.data(), static_cast<DWORD>(wire.size()), &out, sizeof(out), &n);
    if (FAILED(hr)) throw Error{"filter policy transaction", static_cast<DWORD>(hr)};
    expect(n == sizeof(out) && out.Version == ASF_PROTOCOL, "control protocol version");
    return out;
}

// Refuse to execute either fixture role with an elevated or administrator-enabled token.
DWORD tokenIntegrity(HANDLE token) {
    DWORD n = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &n);
    std::vector<BYTE> data(n);
    need(GetTokenInformation(token, TokenIntegrityLevel, data.data(), n, &n) != 0, "get integrity level");
    PSID sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(data.data())->Label.Sid;
    return *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
}
void requireOrdinary(HANDLE token) {
    DWORD n = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &n);
    std::vector<BYTE> data(n);
    need(GetTokenInformation(token, TokenGroups, data.data(), n, &n) != 0, "get token groups");
    auto groups = reinterpret_cast<TOKEN_GROUPS*>(data.data());
    for (DWORD i = 0; i != groups->GroupCount; ++i)
        expect(!(groups->Groups[i].Attributes & SE_GROUP_ENABLED) ||
            !IsWellKnownSid(groups->Groups[i].Sid, WinBuiltinAdministratorsSid), "no enabled administrator group");
    expect(tokenIntegrity(token) <= SECURITY_MANDATORY_MEDIUM_RID,
           "medium or lower integrity");
}
void fixtureToken(Handle& childToken) {
    Handle source;
    need(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                          &source.h) != 0, "open broker token");
    alignas(DWORD) BYTE admin[SECURITY_MAX_SID_SIZE], medium[SECURITY_MAX_SID_SIZE];
    DWORD a = sizeof(admin), b = sizeof(medium);
    need(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin, &a) &&
         CreateWellKnownSid(WinMediumLabelSid, nullptr, medium, &b), "build token identities");
    SID_AND_ATTRIBUTES disable{admin, 0};
    need(CreateRestrictedToken(source.h, DISABLE_MAX_PRIVILEGE, 1, &disable, 0, nullptr,
                               0, nullptr, &childToken.h) != 0, "create restricted fixture token");
    if (tokenIntegrity(childToken.h) > SECURITY_MANDATORY_MEDIUM_RID) {
        TOKEN_MANDATORY_LABEL label{{medium, SE_GROUP_INTEGRITY}};
        need(SetTokenInformation(childToken.h, TokenIntegrityLevel, &label, sizeof(label) + b) != 0, "lower to medium integrity");
    }
    requireOrdinary(childToken.h);
}
void waitSuccess(HANDLE proc) {
    expect(WaitForSingleObject(proc, 15000) == WAIT_OBJECT_0, "wait for fixture completion");
    DWORD code = 0;
    need(GetExitCodeProcess(proc, &code) != 0, "get fixture exit");
    if (code != 0) throw Error{"fixture reported failure", code};
}
int child(const std::wstring& root, const std::wstring& mode) {
    Handle token;
    need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.h) != 0, "check fixture token");
    requireOrdinary(token.h);
    const auto prefix = tempDir() + L"AppShieldFilterLab.{";
    expect(root.size() == prefix.size() + 37 && root.compare(0, prefix.size(), prefix) == 0 &&
        root.back() == L'}' && root.find_first_not_of(L"0123456789abcdefABCDEF-", prefix.size()) == root.size()-1,
        "validate synthetic path");
    if (mode == L"--baseline") {
        readMarker(root + L"\\private\\hidden.txt", "private");
        readMarker(root + L"\\shared\\read.txt", "allowed");
        for (const auto* name : {L"\\shared\\read.txt", L"\\write\\change.txt"}) {
            Handle h(CreateFileW((root + name).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            need(h.h != INVALID_HANDLE_VALUE, "same-token baseline can obtain a write handle");
        }
        return 0;
    }
    const bool leaf = mode == L"--leaf";
    if (leaf) waitRelease(root + L"\\shared\\release.txt");
    readMarker(root + L"\\shared\\read.txt", "allowed");
    denyOpen(root + L"\\private\\hidden.txt", GENERIC_READ);
    denyOpen(root + L"\\shared\\read.txt", GENERIC_WRITE);
    denyOpen(root + L"\\write\\change.txt", DELETE);
    denyOpen(root + L"\\write\\change.txt", WRITE_DAC);
    if (!leaf) {
        overwriteExisting(root + L"\\write\\change.txt", "after!");
        auto exe = modulePath(), args = L"\"" + exe + L"\" --leaf \"" + root + L"\"";
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        need(CreateProcessW(exe.c_str(), args.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, nullptr, &si, &pi) != 0, "start descendant under inherited policy");
        Handle p(pi.hProcess), t(pi.hThread);
    } else overwriteExisting(root + L"\\write\\result.txt", "passed");
    return 0;
}
struct Fixtures {
    const std::wstring root = uniqueRoot();
    HANDLE ordinary;
    std::vector<std::wstring> folders, files;
    explicit Fixtures(HANDLE token) : ordinary(token) { folders.reserve(4); files.reserve(5); }
    void addDir(const std::wstring& p) {
        FixtureIdentity access(ordinary);
        need(CreateDirectoryW(p.c_str(), nullptr) != 0, "create exclusive fixture directory");
        folders.push_back(p);
    }
    void addFile(const std::wstring& p, const char *value) {
        FixtureIdentity access(ordinary);
        createMarker(p, value); files.push_back(p);
    }
    bool cleanup() {
        if (folders.empty()) return true;
        FixtureIdentity access(ordinary);
        for (const auto& dir : folders) {
            DWORD attrs = GetFileAttributesW(dir.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) || !(attrs & FILE_ATTRIBUTE_DIRECTORY)))
                return false;
        }
        bool ok = true;
        for (const auto& f : files) if (!DeleteFileW(f.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) ok = false;
        for (auto i = folders.rbegin(); i != folders.rend(); ++i)
            if (!RemoveDirectoryW(i->c_str()) && GetLastError() != ERROR_PATH_NOT_FOUND) ok = false;
        if (ok) { files.clear(); folders.clear(); }
        return ok;
    }
    ~Fixtures() {
        try { if (!cleanup()) std::fputs("FAIL synthetic cleanup\n", stderr); }
        catch (...) { std::fputs("FAIL fixture cleanup identity\n", stderr); }
    }
};
void verify(Handle& port, bool baselineOnly) {
    Handle restricted;
    fixtureToken(restricted);
    Fixtures f(restricted.h);
    f.addDir(f.root);
    for (const auto* name : {L"private", L"shared", L"write"}) f.addDir(f.root + L"\\" + name);
    f.addFile(f.root + L"\\private\\hidden.txt", "private");
    f.addFile(f.root + L"\\shared\\read.txt", "allowed");
    f.addFile(f.root + L"\\shared\\release.txt", "0");
    f.addFile(f.root + L"\\write\\change.txt", "before");
    f.addFile(f.root + L"\\write\\result.txt", "unseen");
    readMarker(f.root + L"\\private\\hidden.txt", "private");
    readMarker(f.root + L"\\shared\\read.txt", "allowed");
    auto exe = modulePath();
    std::vector<ASF_RULE> rules{
        rootRule(windowsDir(), ASF_READ), rootRule(exe.substr(0, exe.find_last_of(L'\\')), ASF_READ),
        rootRule(f.root + L"\\shared", ASF_READ), rootRule(f.root + L"\\write", ASF_READ | ASF_WRITE)
    };
    auto priv = rootRule(f.root + L"\\private", ASF_READ);
    for (const auto& allowed : rules) {
        std::wstring hidden(priv.Path), grant(allowed.Path);
        expect(hidden != grant && hidden.compare(0, grant.size() + 1, grant + L"\\") != 0,
               "fixture private directory independent of runtime grants");
    }
    const auto cwd = f.root + L"\\shared";
    Handle job(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    need(job.h && SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits)), "scope fixture job");
    {
        auto base = L"\"" + exe + L"\" --baseline \"" + f.root + L"\"";
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        need(CreateProcessAsUserW(restricted.h, exe.c_str(), base.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, cwd.c_str(), &si, &pi) != 0, "start same-token baseline");
        Handle process(pi.hProcess), thread(pi.hThread);
        if (!baselineOnly) expect(request(port.h, ASF_QUERY, process.h).HandleBound == 0, "baseline token has no filter policy");
        try { waitSuccess(process.h); }
        catch (...) { TerminateProcess(process.h, 1); WaitForSingleObject(process.h, 5000); throw; }
    }
    if (baselineOnly) {
        expect(f.cleanup(), "cleanup unbound baseline fixtures");
        std::puts("PASS unbound baseline: same reduced token can read and write synthetic fixtures; kernel enforcement untested");
        return;
    }
    auto cmd = L"\"" + exe + L"\" --child \"" + f.root + L"\"";
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    need(CreateProcessAsUserW(restricted.h, exe.c_str(), cmd.data(), nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, cwd.c_str(), &si, &pi) != 0, "create suspended synthetic child");
    Handle process(pi.hProcess), thread(pi.hThread);
    try {
        need(AssignProcessToJobObject(job.h, process.h) != 0, "bound fixture lifetime");
        expect(request(port.h, ASF_BIND, process.h, rules).HandleBound == 1, "attach policy before resume");
        expect(request(port.h, ASF_QUERY, process.h).HandleBound == 1, "verify exact process policy");
        port.close(); // A disconnect must not weaken the process's existing policy.
        need(ResumeThread(thread.h) != static_cast<DWORD>(-1), "resume bound fixture");
        waitSuccess(process.h);
        connect(port);
        expect(request(port.h, ASF_QUERY, process.h).HandleBound == 0, "release exiting process policy");
        {
            FixtureIdentity access(restricted.h);
            overwriteExisting(f.root + L"\\shared\\release.txt", "1");
        }
        bool drained = false;
        for (unsigned i = 0; i < 200; ++i) {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};
            need(QueryInformationJobObject(job.h, JobObjectBasicAccountingInformation, &info, sizeof(info), nullptr) != 0,
                 "query fixture descendants");
            if (!info.ActiveProcesses) { drained = true; break; }
            Sleep(100);
        }
        expect(drained, "all descendants terminated");
    } catch (...) {
        TerminateProcess(process.h, 1);
        TerminateJobObject(job.h, 1);
        WaitForSingleObject(process.h, 5000);
        throw;
    }
    readMarker(f.root + L"\\write\\change.txt", "after!");
    readMarker(f.root + L"\\write\\result.txt", "passed");
    readMarker(f.root + L"\\private\\hidden.txt", "private");
    expect(f.cleanup(), "cleanup successful fixture run");
    std::puts("PASS host and same-token controls, create-suspended binding, read denial, read grant, read-only denial, writable grant, child policy after parent exit, broker disconnect and exit cleanup");
}
} // namespace
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring(argv[1]) == L"policy-test") return policyChecks();
        if (argc == 2 && std::wstring(argv[1]) == L"baseline-test") {
            Handle noPort; verify(noPort, true); return 0;
        }
        if (argc == 3 && (std::wstring(argv[1]) == L"--baseline" || std::wstring(argv[1]) == L"--child" ||
            std::wstring(argv[1]) == L"--leaf")) return child(argv[2], argv[1]);
        if (argc != 2 || (std::wstring(argv[1]) != L"status" && std::wstring(argv[1]) != L"verify")) return 2;
        Handle port; connect(port);
        const auto hello = request(port.h, ASF_QUERY, nullptr);
        std::printf("Filter protocol %lu, bound processes %lu\n", hello.Version, hello.ManagedProcesses);
        if (std::wstring(argv[1]) == L"verify") verify(port, false);
        return 0;
    } catch (const Error& e) {
        std::fprintf(stderr, "FAIL %s (0x%08lx)\n", e.stage, e.status);
        return 1;
    } catch (const std::exception&) {
        std::fputs("FAIL fixture setup or allocation\n", stderr); return 1;
    }
}
