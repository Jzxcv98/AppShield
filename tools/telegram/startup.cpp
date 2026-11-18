// SPDX-License-Identifier: GPL-3.0-only
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#include <objbase.h>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

namespace {
struct Failure { const char* stage; DWORD code; };
void check(BOOL success, const char* stage) {
    if (!success) throw Failure{stage, GetLastError()};
}
void checkHr(HRESULT result, const char* stage) {
    if (result != S_OK) throw Failure{stage, static_cast<DWORD>(result)};
}
struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    explicit Handle(HANDLE initial = nullptr) : value(initial) {}
};
struct Attributes {
    std::vector<BYTE> storage;
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
    explicit Attributes(DWORD count) {
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, count, 0, &size);
        storage.resize(size);
        auto ptr = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        check(InitializeProcThreadAttributeList(ptr, count, 0, &size), "init_attributes");
        list = ptr;
    }
    ~Attributes() { DeleteProcThreadAttributeList(list); }
};

bool expectedToken(HANDLE process, PSID sid, PSID internet) {
    Handle token;
    check(OpenProcessToken(process, TOKEN_QUERY, &token.value), "open_process_token");
    DWORD size = 0, boxed = 0;
    check(GetTokenInformation(token.value, TokenIsAppContainer, &boxed, sizeof(boxed), &size), "is_appcontainer");
    if (!sid || !boxed) return false;
    GetTokenInformation(token.value, TokenAppContainerSid, nullptr, 0, &size);
    std::vector<BYTE> buf(size);
    check(GetTokenInformation(token.value, TokenAppContainerSid, buf.data(), size, &size), "get_container_sid");
    PSID actual = reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(buf.data())->TokenAppContainer;
    if (!actual || !EqualSid(actual, sid)) return false;
    size = 0;
    GetTokenInformation(token.value, TokenCapabilities, nullptr, 0, &size);
    buf.resize(size);
    check(GetTokenInformation(token.value, TokenCapabilities, buf.data(), size, &size), "query_capabilities");
    auto groups = reinterpret_cast<const TOKEN_GROUPS*>(buf.data());
    if (!internet) return groups->GroupCount == 0;
    return groups->GroupCount == 1 && EqualSid(groups->Groups[0].Sid, internet)
        && (groups->Groups[0].Attributes & SE_GROUP_ENABLED);
}

std::wstring profileFolder(PSID sid) {
    LPWSTR sidString = nullptr, raw = nullptr;
    check(ConvertSidToStringSidW(sid, &sidString), "format_sid");
    HRESULT result = GetAppContainerFolderPath(sidString, &raw);
    LocalFree(sidString);
    checkHr(result, "get_profile_directory");
    std::wstring root(raw);
    CoTaskMemFree(raw);
    return root;
}

std::wstring safeEnvironment(const std::wstring& root) {
    wchar_t windows[MAX_PATH];
    UINT n = GetWindowsDirectoryW(windows, MAX_PATH);
    if (!n || n >= MAX_PATH) throw Failure{"windows_directory", GetLastError()};
    // Explicit, sorted Unicode environment. The target receives no inherited credentials.
    const std::wstring system(windows), temp = root + L"\\ProbeTmp";
    std::vector<std::wstring> variables = {
        L"APPDATA=" + root, L"LOCALAPPDATA=" + root, L"PATH=" + system + L"\\System32",
        L"SystemDrive=" + system.substr(0, 2), L"SystemRoot=" + system, L"TEMP=" + temp,
        L"TMP=" + temp, L"USERPROFILE=" + root, L"WINDIR=" + system
    };
    std::wstring env;
    for (const auto& variable : variables) { env += variable; env.push_back(0); }
    env.push_back(0);
    return env;
}

struct WindowsForPid { DWORD pid; HWND visible; };
BOOL CALLBACK inspectWindow(HWND hwnd, LPARAM ctx) {
    auto& state = *reinterpret_cast<WindowsForPid*>(ctx);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    RECT bounds{};
    if (state.visible || pid != state.pid || !IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER)
        || (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW)) return TRUE;
    wchar_t className[256];
    if (GetClassNameW(hwnd, className, 256) && wcscmp(className, L"#32770") != 0
        && GetWindowRect(hwnd, &bounds) && bounds.right > bounds.left && bounds.bottom > bounds.top)
        state.visible = hwnd;
    return TRUE;
}

bool loggedWorkingDirMatches(std::string_view value, const std::wstring& work) {
    while (!value.empty() && (value.back() == '\r' || value.back() == '/' || value.back() == '\\')) value.remove_suffix(1);
    std::wstring path(value.size(), 0);
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        path.data(), static_cast<int>(path.size()));
    if (count <= 0) return false;
    path.resize(count);
    std::replace(path.begin(), path.end(), L'/', L'\\');
    return CompareStringOrdinal(path.c_str(), count, work.c_str(), static_cast<int>(work.size()), TRUE) == CSTR_EQUAL;
}

enum class LoggedWorkdir { unavailable, matches, differs };
LoggedWorkdir reportStartupMarkers(const std::wstring& work) {
    // Only this run's work directory and upstream's fixed startup log names are eligible.
    // Run after the job has stopped. Avoid redirected paths, devices and multiply linked files.
    struct Marker { const char* output; const char* prefix; bool seen = false; };
    Marker markers[] = {
        {"windows_init", "WinRT Supported:"}, {"ipc_connect", "Connecting local socket"},
        {"other_instance_connected", "Socket connected,"}, {"other_instance_reply", "Show command response received,"},
        {"primary_instance", "This is the only instance"}, {"ipc_listen_failed", "Failed to start listening"},
        {"many_instance_flag", "App Info: Detected another"}, {"main_log", "Moved logging from"},
        {"display_init", "Global devicePixelRatio:"}, {"qt_app_init", "Qt version:"}
    };
    bool readable = false, qtListenerFailure = false;
    LoggedWorkdir logged = LoggedWorkdir::unavailable;
    DWORD dir = GetFileAttributesW(work.c_str());
    if (dir != INVALID_FILE_ATTRIBUTES && (dir & FILE_ATTRIBUTE_DIRECTORY) && !(dir & FILE_ATTRIBUTE_REPARSE_POINT)) {
        for (int index = -1; index < 10; ++index) {
            std::wstring path = work + (index < 0 ? L"\\log.txt" : L"\\log_start" + std::to_wstring(index) + L".txt");
            HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (raw == INVALID_HANDLE_VALUE) continue;
            Handle file(raw);
            BY_HANDLE_FILE_INFORMATION info{};
            if (GetFileType(raw) != FILE_TYPE_DISK || !GetFileInformationByHandle(raw, &info)
                || info.nNumberOfLinks != 1 || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
                continue;
            std::string bytes(256 * 1024, '\0');
            DWORD count = 0;
            if (!ReadFile(raw, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr)) continue;
            readable = true;
            std::string_view remaining(bytes.data(), count);
            while (!remaining.empty()) {
                auto newline = remaining.find('\n');
                auto line = remaining.substr(0, newline);
                if (line.substr(0, 3) == "\xef\xbb\xbf") line.remove_prefix(3);
                auto timestampEnd = line.find("] ");
                if (!line.empty() && line.front() == '[' && timestampEnd != line.npos && timestampEnd <= 32) {
                    auto message = line.substr(timestampEnd + 2);
                    constexpr std::string_view workPrefix = "Working dir: ";
                    if (message.rfind(workPrefix, 0) == 0 && logged != LoggedWorkdir::differs) {
                        logged = loggedWorkingDirMatches(message.substr(workPrefix.size()), work)
                            ? LoggedWorkdir::matches : LoggedWorkdir::differs;
                    }
                    for (auto& marker : markers) {
                        if (message.rfind(marker.prefix, 0) == 0) marker.seen = true;
                    }
                    if (message.rfind("Failed to start listening", 0) == 0
                        && message.find("QLocalServerPrivate::addListener:") != message.npos) qtListenerFailure = true;
                }
                if (newline == remaining.npos) break;
                remaining.remove_prefix(newline + 1);
            }
        }
    }
    std::printf("DIAGNOSTIC startup_log_readable=%d", int(readable));
    for (const auto& marker : markers) std::printf(" %s=%d", marker.output, int(marker.seen));
    const char* where = logged == LoggedWorkdir::unavailable ? "unavailable" :
        (logged == LoggedWorkdir::matches ? "matches" : "differs");
    std::printf(" qt_listener_error=%d logged_workdir=%s\n", int(qtListenerFailure), where);
    return logged;
}

enum class Sample { window, earlyExit, noWindow };
Sample observe(const std::wstring& image, const std::wstring& root, PSID sid,
               PSID internet, const std::wstring& extra, unsigned samples) {
    auto work = root + L"\\ProbeWork";
    auto env = safeEnvironment(root);
    Handle job(CreateJobObjectW(nullptr, nullptr));
    check(job.value != nullptr, "create_job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    check(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)), "configure_job");
    SECURITY_CAPABILITIES caps{};
    caps.AppContainerSid = sid;
    SID_AND_ATTRIBUTES client{internet, SE_GROUP_ENABLED};
    if (internet) { caps.CapabilityCount = 1; caps.Capabilities = &client; }
    Attributes attrs(2);
    check(UpdateProcThreadAttribute(attrs.list, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
        &job.value, sizeof(job.value), nullptr, nullptr), "add_job");
    check(UpdateProcThreadAttribute(attrs.list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &caps, sizeof(caps), nullptr, nullptr), "add_container");
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attrs.list;
    PROCESS_INFORMATION child{};
    std::wstring cmd = L"\"" + image + L"\" -noupdate -workdir \"" + work + L"\"" + extra;
    check(CreateProcessW(image.c_str(), cmd.data(), nullptr, nullptr, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        env.data(), work.c_str(), &startup.StartupInfo, &child), "create_restricted_process");
    Handle process(child.hProcess), thread(child.hThread);
    BOOL inJob = FALSE;
    check(IsProcessInJob(process.value, job.value, &inJob), "query_job");
    std::vector<wchar_t> actual(32768);
    DWORD length = static_cast<DWORD>(actual.size());
    check(QueryFullProcessImageNameW(process.value, 0, actual.data(), &length), "query_image");
    if (!inJob || !expectedToken(process.value, sid, internet) || _wcsicmp(image.c_str(), actual.data()) != 0)
        throw Failure{"process_identity_mismatch", ERROR_INVALID_DATA};
    std::printf("PASS image and job verified, token=appcontainer_sid_verified, capabilities=%s, pid=%lu\n",
        internet ? "internetClient_only" : "none", child.dwProcessId);
    std::fflush(stdout);
    check(ResumeThread(thread.value) != static_cast<DWORD>(-1), "resume");

    unsigned streak = 0;
    HWND previous = nullptr;
    Sample result = Sample::noWindow;
    for (unsigned i = 0; i < samples; ++i) {
        DWORD wait = WaitForSingleObject(process.value, 500);
        if (wait == WAIT_OBJECT_0) {
            DWORD code = 0;
            check(GetExitCodeProcess(process.value, &code), "get_exit_code");
            std::printf("OBSERVED target exited at sample %u, exit=0x%08lx\n", i + 1, code);
            result = Sample::earlyExit;
            break;
        }
        check(wait == WAIT_TIMEOUT, "wait_for_process");
        WindowsForPid windows{child.dwProcessId, nullptr};
        check(EnumWindows(inspectWindow, reinterpret_cast<LPARAM>(&windows)), "enumerate_top_level_windows");
        if (windows.visible != previous) streak = 0;
        previous = windows.visible;
        if (previous) ++streak;
        if (i + 1 == samples) {
            std::printf("OBSERVED target alive after %u ms, final visible-window streak=%u samples\n", samples * 500, streak);
            if (streak >= 3) result = Sample::window;
        }
    }
    check(TerminateJobObject(job.value, 0), "end_test_job");
    for (unsigned i = 0; i != 100; ++i) {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION count{};
        check(QueryInformationJobObject(job.value, JobObjectBasicAccountingInformation, &count, sizeof(count), nullptr), "query_job_shutdown");
        if (!count.ActiveProcesses) return result;
        Sleep(100);
    }
    throw Failure{"wait_for_job_shutdown", WAIT_TIMEOUT};
}

// The controls use this same binary as a lightweight stand-in for a GUI client.
int syntheticGui(bool early) {
    if (early) return 17;
    HWND window = CreateWindowExW(WS_EX_NOACTIVATE, L"STATIC", L"AppShield test control", WS_OVERLAPPEDWINDOW,
        0, 0, 160, 72, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!window) return 18;
    ShowWindow(window, SW_SHOWNOACTIVATE);
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && std::wstring(argv[1]) == L"-noupdate")
        return syntheticGui(std::wstring(argv[argc - 1]) == L"--exit-control");
    if (argc != 5) return 2;
    std::wstring mode = argv[1], id = argv[2], original = argv[3];
    const std::wstring cap = argv[4];
    if ((mode != L"--controls" && mode != L"--installed" && mode != L"--copy")
        || (cap != L"none" && cap != L"internet-client")
        || id.size() != 32 || id.find_first_not_of(L"0123456789abcdef") != std::wstring::npos) return 2;
    std::wstring name = L"AppShield.TgProbe." + id;
    std::printf("RUN temporary_profile=%ls\n", name.c_str());
    std::fflush(stdout);
    PSID sid = nullptr;
    HRESULT create = CreateAppContainerProfile(name.c_str(), L"AppShield startup test", L"Temporary client probe", nullptr, 0, &sid);
    if (create != S_OK) { std::printf("FAIL create_new_profile HRESULT=0x%08lx\n", static_cast<DWORD>(create)); return 1; }
    int result = 1;
    try {
        const std::wstring root = profileFolder(sid);
        check(CreateDirectoryW((root + L"\\ProbeWork").c_str(), nullptr), "create_empty_workdir");
        check(CreateDirectoryW((root + L"\\ProbeTmp").c_str(), nullptr), "create_temp");
        std::wstring image = original;
        if (mode != L"--installed") {
            image = root + L"\\Telegram.exe";
            check(CopyFileW(original.c_str(), image.c_str(), TRUE), "copy_selected_executable");
        }
        alignas(DWORD) BYTE clientSid[SECURITY_MAX_SID_SIZE];
        DWORD length = sizeof(clientSid);
        PSID internet = nullptr;
        if (cap == L"internet-client") {
            check(CreateWellKnownSid(WinCapabilityInternetClientSid, nullptr, clientSid, &length), "create_client_sid");
            internet = clientSid;
        }
        Sample sample = observe(image, root, sid,
            internet, L"", mode == L"--controls" ? 5 : 30);
        if (mode == L"--controls") {
            Sample negative = observe(image, root, sid, internet, L" --exit-control", 5);
            result = (sample == Sample::window && negative == Sample::earlyExit) ? 0 : 1;
        } else {
            // Check the name in this run's initially empty directory only.
            DWORD flags = GetFileAttributesW((root + L"\\ProbeWork\\tdata").c_str());
            bool privateState = flags != INVALID_FILE_ATTRIBUTES && (flags & FILE_ATTRIBUTE_DIRECTORY)
                && !(flags & FILE_ATTRIBUTE_REPARSE_POINT);
            std::printf("OBSERVED tdata directory in new workdir=%s\n", privateState ? "present" : "unconfirmed");
            const auto logged = reportStartupMarkers(root + L"\\ProbeWork");
            result = sample == Sample::window && privateState && logged != LoggedWorkdir::differs ? 0 : 1;
        }
    } catch (const Failure& error) {
        std::printf("FAIL %s code=0x%08lx\n", error.stage, error.code);
    } catch (...) { std::puts("FAIL unexpected probe exception"); }
    FreeSid(sid);
    HRESULT removed = DeleteAppContainerProfile(name.c_str());
    for (unsigned retry = 0; retry < 4 && (removed == E_ACCESSDENIED ||
            removed == HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION)); ++retry) {
        Sleep(500);
        removed = DeleteAppContainerProfile(name.c_str());
    }
    if (removed != S_OK) { std::printf("FAIL remove_test_profile HRESULT=0x%08lx\n", static_cast<DWORD>(removed)); return 1; }
    std::puts("PASS temporary AppContainer profile removed");
    return result;
}
