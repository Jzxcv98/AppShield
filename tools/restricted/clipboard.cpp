// SPDX-License-Identifier: GPL-3.0-only
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <sddl.h>
#include <shellapi.h>
#include <userenv.h>
#include <cstdio>
#include <cstring>
#include <exception>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "userenv.lib")

namespace {
constexpr wchar_t hostMarker[] = L"APPSHIELD_SYNTHETIC_HOST_CLIPBOARD";
constexpr wchar_t childMarker[] = L"APPSHIELD_SYNTHETIC_CHILD_CLIPBOARD";
constexpr DWORD childResult = 0x4a530000;
constexpr DWORD uiLimits =
    JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD | JOB_OBJECT_UILIMIT_DESKTOP;
struct Failure {
    const char *stage;
    DWORD code;
};
void check(bool yes, const char *stage) {
    if (!yes)
        throw Failure{stage, GetLastError()};
}
struct Handle {
    HANDLE value{};
    explicit Handle(HANDLE h = nullptr) : value(h) {}
    ~Handle() {
        if (value)
            CloseHandle(value);
    }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
};
std::wstring objectName(HANDLE h) {
    DWORD count = 0;
    GetUserObjectInformationW(h, UOI_NAME, nullptr, 0, &count);
    check(count >= sizeof(wchar_t), "query UI object name size");
    std::vector<wchar_t> buffer(count / sizeof(wchar_t) + 1);
    check(GetUserObjectInformationW(h, UOI_NAME, buffer.data(), count, &count) != FALSE,
          "query UI object name");
    return buffer.data();
}
std::wstring newDesktopName() {
    const std::wstring prefix = L"AppShield.Clipboard.";
    GUID g{};
    check(CoCreateGuid(&g) == S_OK, "new desktop ID");
    wchar_t id[40]{};
    check(StringFromGUID2(g, id, 40) > 0, "desktop ID");
    return prefix + std::wstring(id + 1, 36);
}
void requirePrivateContext(const std::wstring &name) {
    auto split = name.find(L'\\');
    std::wstring desktop = split == name.npos ? L"" : name.substr(split + 1);
    const std::wstring prefix = L"AppShield.Clipboard.";
    if (desktop.compare(0, prefix.size(), prefix) != 0 || desktop.size() != prefix.size() + 36)
        throw Failure{"expected unique synthetic desktop name", ERROR_INVALID_NAME};
    GUID validated{};
    if (FAILED(CLSIDFromString((L"{" + desktop.substr(prefix.size()) + L"}").c_str(), &validated)))
        throw Failure{"invalid synthetic desktop ID", ERROR_INVALID_NAME};
    auto station = GetProcessWindowStation();
    USEROBJECTFLAGS info{};
    DWORD size = 0;
    check(GetUserObjectInformationW(station, UOI_FLAGS, &info, sizeof(info), &size) != FALSE,
          "window station flags");
    if (info.dwFlags & WSF_VISIBLE || objectName(station) != name.substr(0, split) ||
        objectName(GetThreadDesktop(GetCurrentThreadId())) != desktop)
        throw Failure{"refused clipboard outside the synthetic station", ERROR_ACCESS_DENIED};
}
struct MarkerWindow {
    HWND hwnd{};
    explicit MarkerWindow(const std::wstring &station) {
        requirePrivateContext(station);
        hwnd = CreateWindowExW(0, L"STATIC", L"AppShield clipboard test", 0, 0, 0, 0, 0, HWND_MESSAGE,
                               nullptr, GetModuleHandleW(nullptr), nullptr);
        check(hwnd != nullptr, "create clipboard owner");
    }
    ~MarkerWindow() {
        if (hwnd)
            DestroyWindow(hwnd);
    }
};
struct Clipboard {
    bool opened;
    Clipboard(const std::wstring &station, HWND w) {
        requirePrivateContext(station);
        opened = OpenClipboard(w) != FALSE;
    }
    ~Clipboard() {
        if (opened)
            CloseClipboard();
    }
};
enum ResultBits : DWORD {
    ReadMarker = 1,
    Published = 2,
    OpenedForWrite = 4,
    Emptied = 8,
    CreatedWindow = 16
};
DWORD put(const std::wstring &station, HWND hwnd, const wchar_t *value) {
    Clipboard clipboard(station, hwnd);
    if (!clipboard.opened)
        return 0;
    if (!EmptyClipboard())
        return OpenedForWrite;
    size_t bytes = (wcslen(value) + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    check(mem != nullptr, "allocate synthetic clipboard text");
    void *ptr = GlobalLock(mem);
    if (!ptr) {
        GlobalFree(mem);
        throw Failure{"lock synthetic text", ERROR_NOT_ENOUGH_MEMORY};
    }
    memcpy(ptr, value, bytes);
    GlobalUnlock(mem);
    if (SetClipboardData(CF_UNICODETEXT, mem))
        return OpenedForWrite | Emptied | Published;
    GlobalFree(mem);
    return OpenedForWrite | Emptied;
}
bool contains(const std::wstring &station, HWND hwnd, const wchar_t *expected) {
    Clipboard clipboard(station, hwnd);
    if (!clipboard.opened)
        return false;
    HANDLE data = GetClipboardData(CF_UNICODETEXT);
    if (!data)
        return false;
    size_t bytes = (wcslen(expected) + 1) * sizeof(wchar_t);
    if (GlobalSize(data) < bytes)
        return false;
    void *p = GlobalLock(data);
    if (!p)
        return false;
    bool result = memcmp(p, expected, bytes) == 0;
    GlobalUnlock(data);
    return result;
}
std::wstring textSid(PSID sid) {
    LPWSTR value = nullptr;
    check(ConvertSidToStringSidW(sid, &value) != FALSE, "format SID");
    std::wstring result(value);
    LocalFree(value);
    return result;
}
std::wstring hostSid() {
    Handle token;
    check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value) != FALSE, "owner token");
    DWORD bytes = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
    std::vector<BYTE> buffer(bytes);
    check(bytes && GetTokenInformation(token.value, TokenUser, buffer.data(), bytes, &bytes),
          "owner SID");
    return textSid(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid);
}
std::wstring profileName(const std::wstring &desktop) {
    return L"AppShield.ClipProfile." + desktop.substr(desktop.rfind(L'.') + 1);
}
std::wstring permissions(const std::wstring &desktop, bool deny) {
    PSID sid = nullptr;
    check(SUCCEEDED(DeriveAppContainerSidFromAppContainerName(profileName(desktop).c_str(), &sid)),
          "derive fixture AppContainer SID");
    auto app = textSid(sid);
    FreeSid(sid);
    auto denied = deny ? L"(D;;0x4;;;" + app + L")" : std::wstring();
    return L"D:P" + denied + L"(A;OICI;GA;;;SY)(A;OICI;GA;;;" + hostSid() + L")(A;OICI;GA;;;" + app +
           L")S:(ML;;NW;;;LW)";
}
struct Fixture {
    HWINSTA originalStation = GetProcessWindowStation();
    HDESK originalDesktop = GetThreadDesktop(GetCurrentThreadId());
    HWINSTA station{};
    HDESK desktop{};
    std::wstring name;
    void prepare(const std::wstring &named = L"", bool openExisting = false,
                 bool provisionOnly = false) {
        // An unprivileged interactive user may create an unnamed station. CREATE_ONLY
        // refuses any existing station (including that logon session's service station).
        // Restrict this scratch object to the user shared by the two test processes.
        const auto desk = named.empty() ? newDesktopName() : named;
        std::wstring sddl = permissions(desk, false);
        PSECURITY_DESCRIPTOR sd = nullptr;
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd,
                                                                   nullptr) != FALSE,
              "private station DACL");
        SECURITY_ATTRIBUTES acl{sizeof(SECURITY_ATTRIBUTES), sd, FALSE};
        DWORD rights = WINSTA_ALL_ACCESS | READ_CONTROL | WRITE_DAC;
        station = openExisting ? OpenWindowStationW(named.c_str(), FALSE, rights)
                               : CreateWindowStationW(named.empty() ? nullptr : named.c_str(),
                                                      CWF_CREATE_ONLY, rights, &acl);
        DWORD error = GetLastError();
        if (!station) {
            LocalFree(sd);
            throw Failure{"create/open private window station", error};
        }
        if (!SetProcessWindowStation(station)) {
            error = GetLastError();
            LocalFree(sd);
            throw Failure{"select private station", error};
        }
        desktop = openExisting ? OpenDesktopW(desk.c_str(), 0, FALSE, GENERIC_ALL)
                               : CreateDesktopW(desk.c_str(), nullptr, nullptr, 0, GENERIC_ALL, &acl);
        error = GetLastError();
        LocalFree(sd);
        SetLastError(error);
        check(desktop != nullptr, "create private desktop");
        if (provisionOnly)
            return;
        check(SetThreadDesktop(desktop) != FALSE, "select private desktop");
        name = objectName(station) + L"\\" + desk;
        requirePrivateContext(name);
    }
    void denyProfileClipboard() {
        requirePrivateContext(name);
        auto sddl = permissions(name.substr(name.find(L'\\') + 1), true);
        PSECURITY_DESCRIPTOR sd = nullptr;
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd,
                                                                   nullptr) != FALSE,
              "build isolated station rule");
        SECURITY_INFORMATION parts = DACL_SECURITY_INFORMATION;
        BOOL ok = SetUserObjectSecurity(station, &parts, sd);
        DWORD error = GetLastError();
        LocalFree(sd);
        if (!ok)
            throw Failure{"apply clipboard deny to fixture alone", error};
    }
    ~Fixture() {
        if (station)
            SetProcessWindowStation(originalStation);
        if (desktop)
            SetThreadDesktop(originalDesktop);
        if (desktop)
            CloseDesktop(desktop);
        if (station)
            CloseWindowStation(station);
    }
};
struct Profile {
    PSID sid{};
    std::wstring name, image;
    void create(const std::wstring &desktop) {
        name = profileName(desktop);
        HRESULT status = CreateAppContainerProfile(name.c_str(), L"AppShield test clipboard",
                                                   L"Temporary test", nullptr, 0, &sid);
        if (status != S_OK) {
            sid = nullptr;
            throw Failure{"create clipboard test profile", static_cast<DWORD>(status)};
        }
        PWSTR raw = nullptr;
        status = GetAppContainerFolderPath(textSid(sid).c_str(), &raw);
        if (status != S_OK)
            throw Failure{"clipboard test profile folder", static_cast<DWORD>(status)};
        image = std::wstring(raw) + L"\\clipboard-test.exe";
        CoTaskMemFree(raw);
        wchar_t exe[32768]{};
        DWORD n = GetModuleFileNameW(nullptr, exe, 32768);
        check(n && n < 32768 && CopyFileW(exe, image.c_str(), TRUE),
              "stage only the synthetic clipboard executable");
    }
    void close() {
        if (!sid)
            return;
        auto result = DeleteAppContainerProfile(name.c_str());
        if (result != S_OK) {
            std::printf("FAIL test profile cleanup %ls\n", name.c_str());
            throw Failure{"delete clipboard test profile", static_cast<DWORD>(result)};
        }
        FreeSid(sid);
        sid = nullptr;
    }
    ~Profile() {
        if (sid) {
            DeleteAppContainerProfile(name.c_str());
            FreeSid(sid);
        }
    }
};
struct Attributes {
    std::vector<BYTE> storage;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs{};
    SECURITY_CAPABILITIES capabilities{};
    void set(PSID sid) {
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        storage.resize(bytes);
        auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        check(InitializeProcThreadAttributeList(list, 1, 0, &bytes) != FALSE, "init app capabilities");
        attrs = list;
        capabilities.AppContainerSid = sid;
        check(UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                        &capabilities, sizeof(capabilities), nullptr, nullptr) != FALSE,
              "select test AppContainer");
    }
    ~Attributes() {
        if (attrs)
            DeleteProcThreadAttributeList(attrs);
    }
};
DWORD sample(const std::wstring &station, bool restrict, Profile *profile = nullptr) {
    std::vector<wchar_t> path(32768);
    DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    check(n > 0 && n < path.size(), "test program path");
    std::wstring image = profile ? profile->image : std::wstring(path.data(), n);
    std::wstring command = L"\"" + image + L"\" --child " + station;
    std::wstring desktop = station;
    STARTUPINFOEXW start{};
    start.StartupInfo.cb = profile ? sizeof(start) : sizeof(STARTUPINFOW);
    start.StartupInfo.lpDesktop = desktop.data();
    Attributes attributes;
    if (profile) {
        attributes.set(profile->sid);
        start.lpAttributeList = attributes.attrs;
    }
    Handle job(restrict ? CreateJobObjectW(nullptr, nullptr) : nullptr);
    if (restrict) {
        check(job.value != nullptr, "create test job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        check(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits,
                                      sizeof(limits)) != FALSE,
              "apply job lifetime");
        JOBOBJECT_BASIC_UI_RESTRICTIONS ui{uiLimits};
        check(SetInformationJobObject(job.value, JobObjectBasicUIRestrictions, &ui, sizeof(ui)) != FALSE,
              "apply UI isolation");
    }
    PROCESS_INFORMATION p{};
    check(CreateProcessW(image.c_str(), command.data(), nullptr, nullptr, FALSE,
                         CREATE_SUSPENDED | CREATE_NO_WINDOW |
                             (profile ? EXTENDED_STARTUPINFO_PRESENT : 0),
                         nullptr, nullptr, &start.StartupInfo, &p) != FALSE,
          "create synthetic child");
    Handle process(p.hProcess), thread(p.hThread);
    try {
        if (profile) {
            Handle token;
            check(OpenProcessToken(process.value, TOKEN_QUERY, &token.value) != FALSE, "child token");
            DWORD isApp = 0, len = 0;
            check(GetTokenInformation(token.value, TokenIsAppContainer, &isApp, sizeof(isApp), &len) &&
                      isApp,
                  "actual AppContainer token");
            GetTokenInformation(token.value, TokenAppContainerSid, nullptr, 0, &len);
            std::vector<BYTE> sidInfo(len);
            check(len &&
                      GetTokenInformation(token.value, TokenAppContainerSid, sidInfo.data(), len, &len),
                  "actual AppContainer SID");
            check(
                EqualSid(profile->sid, reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(sidInfo.data())
                                           ->TokenAppContainer) != FALSE,
                "expected AppContainer identity");
        }
        if (restrict) {
            check(AssignProcessToJobObject(job.value, process.value) != FALSE, "assign synthetic job");
            BOOL assigned = FALSE;
            check(IsProcessInJob(process.value, job.value, &assigned) && assigned,
                  "check job membership");
        }
        check(ResumeThread(thread.value) != static_cast<DWORD>(-1), "resume synthetic child");
        check(WaitForSingleObject(process.value, 10000) == WAIT_OBJECT_0, "wait for synthetic child");
        DWORD result = 0;
        check(GetExitCodeProcess(process.value, &result) != FALSE, "child result");
        return result;
    } catch (...) {
        TerminateProcess(process.value, 1);
        WaitForSingleObject(process.value, 5000);
        throw;
    }
}
bool trial(Fixture &fixture, HWND owner, Profile *profile, const char *name) {
    check((put(fixture.name, owner, hostMarker) & Published) != 0, "reset private clipboard baseline");
    DWORD before = GetClipboardSequenceNumber();
    DWORD result = sample(fixture.name, true, profile);
    if (result < childResult || result > childResult + 31) {
        std::printf("OBSERVED %s child status=0x%08lx\n", name, result);
        return false;
    }
    DWORD flags = result - childResult;
    bool unchanged = contains(fixture.name, owner, hostMarker);
    bool formatAvailable = IsClipboardFormatAvailable(CF_UNICODETEXT) != FALSE;
    DWORD after = GetClipboardSequenceNumber();
    std::printf("OBSERVED %s window=%u read_host=%u opened_for_write=%u emptied=%u published=%u "
                "host_unchanged=%u host_text_format=%u sequence_changed=%u\n",
                name, !!(flags & CreatedWindow), !!(flags & ReadMarker), !!(flags & OpenedForWrite),
                !!(flags & Emptied), !!(flags & Published), unchanged, formatAvailable, before != after);
    return bool(flags & CreatedWindow) && !(flags & (ReadMarker | Emptied | Published)) && unchanged;
}
int run(Fixture &fixture) {
    MarkerWindow owner(fixture.name);
    check((put(fixture.name, owner.hwnd, hostMarker) & Published) != 0, "publish synthetic host marker");
    DWORD baseline = sample(fixture.name, false);
    if (baseline != childResult + 31 || !contains(fixture.name, owner.hwnd, childMarker))
        throw Failure{"unrestricted synthetic child baseline", baseline};
    std::puts("PASS ordinary child read and replaced the private station marker");
    trial(fixture, owner.hwnd, nullptr, "job-only");
    Profile profile;
    profile.create(fixture.name.substr(fixture.name.find(L'\\') + 1));
    trial(fixture, owner.hwnd, &profile, "AppContainer+job");
    fixture.denyProfileClipboard();
    bool protectedGui = trial(fixture, owner.hwnd, &profile, "AppContainer+job+station-deny");
    profile.close();
    return protectedGui ? 0 : 1;
}

int testManagedClipboard(Fixture &fixture, const std::wstring &checks) {
    MarkerWindow owner(fixture.name);
    check((put(fixture.name, owner.hwnd, hostMarker) & Published) != 0, "seed private control");
    check(sample(fixture.name, false) == childResult + 31 && contains(fixture.name, owner.hwnd, childMarker),
          "ordinary client can read and publish private clipboard text");
    check((put(fixture.name, owner.hwnd, hostMarker) & Published) != 0, "reset private control");
    std::vector<wchar_t> image(32768);
    DWORD n = GetModuleFileNameW(nullptr, image.data(), static_cast<DWORD>(image.size()));
    check(n && n < image.size(), "get fixture image");
    auto command = L"\"" + checks + L"\" --wechat-clipboard-test private-station \"" +
        std::wstring(image.data(), n) + L"\" " + fixture.name;
    STARTUPINFOW si{sizeof(si)};
    si.lpDesktop = fixture.name.data();
    PROCESS_INFORMATION pi{};
    check(CreateProcessW(checks.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                         nullptr, nullptr, &si, &pi) != FALSE, "start managed job test");
    Handle process(pi.hProcess), thread(pi.hThread);
    if (WaitForSingleObject(process.value, 25000) != WAIT_OBJECT_0) {
        TerminateProcess(process.value, 1);
        throw Failure{"managed job test timeout", WAIT_TIMEOUT};
    }
    DWORD result{};
    check(GetExitCodeProcess(process.value, &result) && result >= childResult && result <= childResult+31,
          "managed fixture receipt");
    DWORD flags = result-childResult;
    std::printf("Managed private station: window=%d read=%d published=%d emptied=%d original_retained=%d\n",
        !!(flags & CreatedWindow), !!(flags & ReadMarker), !!(flags & Published), !!(flags & Emptied),
        contains(fixture.name, owner.hwnd, hostMarker));
    return (flags & CreatedWindow) && !(flags & (ReadMarker | Published)) &&
        !contains(fixture.name, owner.hwnd, childMarker) ? 0 : 1;
}

void checkFixtureName(const std::wstring &name) {
    const std::wstring prefix = L"AppShield.Clipboard.";
    GUID value{};
    if (name.size() != prefix.size() + 36 || name.compare(0, prefix.size(), prefix) != 0 ||
        FAILED(CLSIDFromString((L"{" + name.substr(prefix.size()) + L"}").c_str(), &value)))
        throw Failure{"invalid fixture name", ERROR_INVALID_NAME};
}
std::wstring eventName(const std::wstring &name, const wchar_t *tag) {
    return L"Local\\" + name + tag;
}
int provision(const std::wstring &name) {
    checkFixtureName(name);
    Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName(name, L".Ready").c_str()));
    Handle release(OpenEventW(SYNCHRONIZE, FALSE, eventName(name, L".Release").c_str()));
    check(ready.value && release.value, "open fixture lifecycle events");
    Fixture created;
    created.prepare(name, false, true);
    check(SetEvent(ready.value) != FALSE, "announce fixture");
    check(WaitForSingleObject(release.value, 90000) == WAIT_OBJECT_0, "fixture release");
    return 0;
}
int runWithStationOwner(const std::wstring &managedChecks = L"") {
    // A named window station requires Administrator. The helper creates the UI
    // objects only. This caller and both clipboard clients retain ordinary rights.
    const auto name = newDesktopName();
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, eventName(name, L".Ready").c_str()));
    check(ready.value && GetLastError() != ERROR_ALREADY_EXISTS, "own ready event");
    Handle release(CreateEventW(nullptr, TRUE, FALSE, eventName(name, L".Release").c_str()));
    check(release.value && GetLastError() != ERROR_ALREADY_EXISTS, "own release event");
    std::vector<wchar_t> image(32768);
    DWORD n = GetModuleFileNameW(nullptr, image.data(), static_cast<DWORD>(image.size()));
    check(n > 0 && n < image.size(), "station helper image");
    auto parameters = L"--station-owner " + name;
    SHELLEXECUTEINFOW request{sizeof(request)};
    request.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    request.lpVerb = L"runas";
    request.lpFile = image.data();
    request.lpParameters = parameters.c_str();
    request.nShow = SW_HIDE;
    check(ShellExecuteExW(&request) != FALSE, "station provision approval");
    Handle helper(request.hProcess);
    HANDLE waits[] = {ready.value, helper.value};
    DWORD wait = WaitForMultipleObjects(2, waits, FALSE, 30000);
    if (wait != WAIT_OBJECT_0) {
        SetEvent(release.value);
        DWORD rc = wait;
        if (wait == WAIT_OBJECT_0 + 1)
            GetExitCodeProcess(helper.value, &rc);
        throw Failure{"station provision failed (stage and Win32 status)", rc};
    }
    try {
        int result = 1;
        std::exception_ptr failure;
        // ShellExecuteEx may create COM windows on the caller's thread. Only a
        // thread without windows or hooks can switch to another desktop.
        std::thread worker([&] {
            try {
                Fixture fixture;
                fixture.prepare(name, true);
                result = managedChecks.empty() ? run(fixture) : testManagedClipboard(fixture, managedChecks);
            } catch (...) {
                failure = std::current_exception();
            }
        });
        worker.join();
        if (failure)
            std::rethrow_exception(failure);
        check(SetEvent(release.value) != FALSE, "release station owner");
        check(WaitForSingleObject(helper.value, 5000) == WAIT_OBJECT_0, "wait for station cleanup");
        DWORD rc = 1;
        check(GetExitCodeProcess(helper.value, &rc) && rc == 0, "station cleanup status");
        return result;
    } catch (...) {
        SetEvent(release.value);
        WaitForSingleObject(helper.value, 5000);
        throw;
    }
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        if (argc == 3 && !wcscmp(argv[1], L"--child")) {
            MarkerWindow owner(argv[2]);
            DWORD flags = CreatedWindow;
            if (contains(argv[2], owner.hwnd, hostMarker))
                flags |= ReadMarker;
            flags |= put(argv[2], owner.hwnd, childMarker);
            return static_cast<int>(childResult + flags);
        }
        if (argc == 3 && !wcscmp(argv[1], L"--station-owner")) {
            try {
                return provision(argv[2]);
            } catch (const Failure &f) {
                const char *steps[] = {"invalid fixture name",
                                       "open fixture lifecycle events",
                                       "fixture owner token",
                                       "fixture user SID",
                                       "format fixture SID",
                                       "private station DACL",
                                       "create/open private window station",
                                       "select private station",
                                       "create private desktop",
                                       "select private desktop",
                                       "query UI object name size",
                                       "query UI object name",
                                       "window station flags",
                                       "refused clipboard outside the synthetic station",
                                       "announce fixture"};
                for (unsigned i = 0; i < sizeof(steps) / sizeof(steps[0]); ++i)
                    if (!strcmp(steps[i], f.stage))
                        return static_cast<int>(((i + 1) << 16) | (f.code & 0xffff));
                return static_cast<int>(0xff0000 | (f.code & 0xffff));
            }
        }
        if (argc == 2 && !wcscmp(argv[1], L"--self-test-uac"))
            return runWithStationOwner();
        if (argc == 3 && !wcscmp(argv[1], L"--managed-job-test-uac"))
            return runWithStationOwner(argv[2]);
        if (argc == 2 && !wcscmp(argv[1], L"--self-test")) {
            Fixture fixture;
            fixture.prepare();
            return run(fixture);
        }
    } catch (const Failure &f) {
        std::printf("FAIL %s: 0x%08lx\n", f.stage, f.code);
        return 1;
    }
    return 2;
}
