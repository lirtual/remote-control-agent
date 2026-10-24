// Disposable Windows CI only: exercise the kernel's default AppContainer
// loopback-denial behavior with a positive-control normal process.
// No firewall/WFP policy, network exception, driver, service or user browser.
// IMPORTANT: this does NOT demonstrate Chrome/Edge compatibility or strict
// proxy-only network confinement. See Issue #33.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <userenv.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <stdexcept>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "userenv.lib")

static void require(bool ok, const char* reason) {
  if (!ok) throw std::runtime_error(reason);
}
static std::wstring command(const std::wstring& image, unsigned port) {
  return L"\"" + image + L"\" --child " + std::to_wstring(port);
}
struct Profile {
  std::wstring name;
  PSID sid = nullptr;
  bool created = false;
  ~Profile() {
    if (sid) FreeSid(sid);
    if (created) DeleteAppContainerProfile(name.c_str());
  }
};
static DWORD launch(const std::wstring& exe, unsigned port, PSID packageSid) {
  STARTUPINFOEXW si{};
  si.StartupInfo.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  std::vector<unsigned char> attrs;
  SECURITY_CAPABILITIES caps{};
  LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
  DWORD flags = CREATE_NO_WINDOW;
  if (packageSid) {
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    require(GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytes > 0,
      "Windows refused AppContainer process-attribute sizing");
    attrs.resize(bytes);
    list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrs.data());
    require(InitializeProcThreadAttributeList(list, 1, 0, &bytes) != 0,
      "Windows refused AppContainer attribute initialization");
    caps.AppContainerSid = packageSid;
    require(UpdateProcThreadAttribute(list, 0,
      PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &caps, sizeof(caps),
      nullptr, nullptr) != 0, "Windows refused AppContainer SID attribute");
    si.lpAttributeList = list;
    flags |= EXTENDED_STARTUPINFO_PRESENT;
  }
  std::wstring args = command(exe, port);
  const BOOL started = CreateProcessW(exe.c_str(), args.data(),
    nullptr, nullptr, FALSE, flags, nullptr, nullptr,
    &si.StartupInfo, &pi);
  const DWORD launchError = GetLastError();
  if (list) DeleteProcThreadAttributeList(list);
  if (!started) {
    std::fprintf(stderr, "APPCONTAINER_START_FAILED=%lu\n", launchError);
    throw std::runtime_error("Unable to launch disposable AppContainer child");
  }
  DWORD exit = STILL_ACTIVE;
  std::printf("APPCONTAINER_CHILD_LAUNCHED=%s\n", packageSid ? "sandbox" : "baseline");
  std::fflush(stdout);
  const DWORD wait = WaitForSingleObject(pi.hProcess, 10000);
  if (wait != WAIT_OBJECT_0) {
    std::printf("APPCONTAINER_CHILD_WAIT=%s:%lu\n", packageSid ? "sandbox" : "baseline", wait);
    std::fflush(stdout);
    TerminateProcess(pi.hProcess, 99);
    WaitForSingleObject(pi.hProcess, 2000);
  } else {
    require(GetExitCodeProcess(pi.hProcess, &exit) != 0,
      "Cannot read disposable child exit code");
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  require(wait == WAIT_OBJECT_0, "Disposable child timed out");
  return exit;
}
static bool arrived(SOCKET listener, long microseconds) {
  fd_set reads;
  FD_ZERO(&reads);
  FD_SET(listener, &reads);
  timeval timeout{0, microseconds};
  const int ready = select(0, &reads, nullptr, nullptr, &timeout);
  require(ready != SOCKET_ERROR, "Controlled listener select failed");
  if (ready == 0) return false;
  SOCKET peer = accept(listener, nullptr, nullptr);
  require(peer != INVALID_SOCKET, "Controlled listener accept failed");
  closesocket(peer);
  return true;
}
static int child(unsigned port) {
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 71;
  SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (client == INVALID_SOCKET) { WSACleanup(); return 42; }
  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(static_cast<u_short>(port));
  const int status = connect(client, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
  closesocket(client);
  WSACleanup();
  return status == 0 ? 0 : 42;
}
int wmain(int argc, wchar_t** argv) {
  if (argc == 3 && wcscmp(argv[1], L"--child") == 0) {
    const long port = wcstol(argv[2], nullptr, 10);
    if (port < 1 || port > 65535) return 72;
    return child(static_cast<unsigned>(port));
  }
  if (argc != 1 || GetEnvironmentVariableW(L"GITHUB_ACTIONS", nullptr, 0) == 0) {
    std::fprintf(stderr, "Disposable GitHub Windows CI only\n");
    return 1;
  }
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 2;
  SOCKET listener = INVALID_SOCKET;
  try {
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    require(listener != INVALID_SOCKET, "Loopback listener create failed");
    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bindAddr.sin_port = 0;
    require(bind(listener, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) == 0,
      "Loopback listener bind failed");
    require(listen(listener, 4) == 0, "Loopback listener listen failed");
    int addrSize = sizeof(bindAddr);
    require(getsockname(listener, reinterpret_cast<sockaddr*>(&bindAddr), &addrSize) == 0,
      "Cannot get loopback port");
    const unsigned port = ntohs(bindAddr.sin_port);
    wchar_t exe[MAX_PATH]{};
    require(GetModuleFileNameW(nullptr, exe, MAX_PATH) > 0,
      "Cannot resolve test executable");

    // Unrestricted positive control: a real TCP connection MUST succeed.
    std::puts("APPCONTAINER_BASELINE_START");
    std::fflush(stdout);
    require(launch(exe, port, nullptr) == 0,
      "Unrestricted positive-control child did not connect");
    require(arrived(listener, 200000),
      "Unrestricted positive-control listener saw no connection");

    Profile profile;
    profile.name = L"RCA-CI-" + std::to_wstring(GetCurrentProcessId()) +
      L"-" + std::to_wstring(GetTickCount64());
    const HRESULT hr = CreateAppContainerProfile(profile.name.c_str(),
      L"RCA CI isolated probe", L"Disposable AppContainer network test",
      nullptr, 0, &profile.sid);
    if (FAILED(hr)) {
      std::fprintf(stderr, "APPCONTAINER_PROFILE_CREATE_FAILED=0x%08lx\n",
        static_cast<unsigned long>(hr));
      throw std::runtime_error("AppContainer profile unavailable");
    }
    profile.created = true;
    // No internetClient, privateNetworkClientServer or loopback exemptions.
    std::puts("APPCONTAINER_SANDBOX_START");
    std::fflush(stdout);
    const DWORD result = launch(exe, port, profile.sid);
    std::printf("APPCONTAINER_CHILD_EXIT=%lu\n", result);
    require(result == 42,
      "AppContainer child did not run or failed to deny TCP loopback");
    require(!arrived(listener, 200000),
      "AppContainer made a prohibited direct TCP loopback connection");
    std::puts("WINDOWS_APPCONTAINER_DEFAULT_LOOPBACK=PASS");
    std::puts("WINDOWS_APPCONTAINER_PROXY_ONLY_ISOLATION=NOT_TESTED");
  } catch (const std::exception& error) {
    std::fprintf(stderr, "APPCONTAINER_PROBE_ERROR=%s\n", error.what());
    if (listener != INVALID_SOCKET) closesocket(listener);
    WSACleanup();
    return 1;
  }
  closesocket(listener);
  WSACleanup();
  return 0;
}
