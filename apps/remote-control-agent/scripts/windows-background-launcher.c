// Windowless Windows Task Scheduler entrypoint. No shell, no command interpreter.
// A private job owns the native Node Agent and kills it when the task is stopped.
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <stdio.h>

#define PATH_CAP 32768
static wchar_t executable[PATH_CAP];
static wchar_t node[PATH_CAP];
static wchar_t entry[PATH_CAP];
static wchar_t resolved[PATH_CAP];
static wchar_t command[PATH_CAP];

static int regular_file(const wchar_t *name) {
    DWORD attributes = GetFileAttributesW(name);
    return attributes != INVALID_FILE_ATTRIBUTES &&
        !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}
static int acceptable_endpoint(const wchar_t *value) {
    size_t n = wcslen(value);
    if (n < 11 || n > 256 || wcsncmp(value, L"https://", 8) != 0 ||
        value[n - 1] != L'/') return 0;
    for (size_t i = 8; i < n; ++i) {
        wchar_t c = value[i];
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
              (c >= L'0' && c <= L'9') || c == L'.' || c == L'-' ||
              c == L':' || c == L'/')) return 0;
    }
    for (size_t i = 8; i + 1 < n; ++i) if (value[i] == L'/') return 0;
    return n > 9;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR unused, int show) {
    (void)instance; (void)previous; (void)unused; (void)show;
    int argc = 0, rc = 1;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    HANDLE job = NULL;
    PROCESS_INFORMATION child = {0};
    if (!argv || argc != 5 || wcscmp(argv[2], L"run") ||
        wcscmp(argv[3], L"--endpoint") || !acceptable_endpoint(argv[4])) goto done;
    DWORD count = GetModuleFileNameW(NULL, executable, PATH_CAP);
    if (!count || count >= PATH_CAP) goto done;
    wchar_t *slash = wcsrchr(executable, L'\\');
    if (!slash) goto done;
    slash[1] = L'\0';
    if (swprintf_s(node, PATH_CAP, L"%lsnode.exe", executable) < 0 ||
        swprintf_s(resolved, PATH_CAP,
            L"%ls..\\apps\\remote-control-agent\\src\\windows-v2.js", executable) < 0)
        goto done;
    if (!GetFullPathNameW(resolved, PATH_CAP, entry, NULL) ||
        !regular_file(node) || !regular_file(entry)) goto done;
    if (CompareStringOrdinal(argv[1], -1, entry, -1, TRUE) != CSTR_EQUAL) goto done;
    if (swprintf_s(command, PATH_CAP, L"\"%ls\" \"%ls\" run --endpoint \"%ls\"",
                   node, entry, argv[4]) < 0) goto done;
    job = CreateJobObjectW(NULL, NULL);
    if (!job) goto done;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits))) goto done;
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    if (!CreateProcessW(node, command, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED,
                        NULL, executable, &startup, &child)) goto done;
    if (!AssignProcessToJobObject(job, child.hProcess)) goto done;
    if (ResumeThread(child.hThread) == (DWORD)-1) goto done;
    if (WaitForSingleObject(child.hProcess, INFINITE) != WAIT_OBJECT_0) goto done;
    DWORD exit_code = 1;
    if (!GetExitCodeProcess(child.hProcess, &exit_code)) goto done;
    rc = (int)exit_code;
done:
    if (child.hProcess) {
        if (rc != 0) TerminateProcess(child.hProcess, 1);
        CloseHandle(child.hProcess);
    }
    if (child.hThread) CloseHandle(child.hThread);
    if (job) CloseHandle(job);
    if (argv) LocalFree(argv);
    return rc;
}
