// Disposable Windows CI only: exercise the kernel's default AppContainer
// loopback-denial behavior with a positive-control normal process.
// WFP policy, if supported, is a dynamic per-AppContainer-SID CI experiment.
// No persistent firewall rules, broad exceptions, driver, service or user browser.
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
#include <fwpmu.h>
#include <rpc.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <stdexcept>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

static void require(bool ok, const char* reason) {
  if (!ok) throw std::runtime_error(reason);
}
static std::wstring command(const std::wstring& image, unsigned port, bool health) {
  return L"\"" + image + (health ? L"\" --health" : L"\" --child " + std::to_wstring(port));
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
static DWORD launch(const std::wstring& exe, unsigned port, PSID packageSid, bool health = false) {
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
  std::wstring args = command(exe, port, health);
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
// All test filters use a unique ephemeral package SID. A *dynamic* WFP
// session guarantees automatic object deletion if the test process dies.
// No generic browser exe path, user SID or all-process permit/block filters.
struct WfpExperiment {
  HANDLE engine = nullptr;
  GUID sublayer{};
  explicit WfpExperiment(PSID appSid, unsigned allowedPort) {
    FWPM_SESSION0 session{};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = const_cast<wchar_t*>(L"RCA CI isolated WFP test");
    DWORD rc = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine);
    std::printf("WFP_ENGINE_OPEN=%lu\n", rc);
    require(rc == ERROR_SUCCESS, "Cannot open temporary WFP engine session");
    const RPC_STATUS guidResult = UuidCreate(&sublayer);
    require(guidResult == RPC_S_OK || guidResult == RPC_S_UUID_LOCAL_ONLY,
      "Temporary WFP sublayer GUID unavailable");
    FWPM_SUBLAYER0 layer{};
    layer.subLayerKey = sublayer;
    layer.displayData.name = const_cast<wchar_t*>(L"RCA CI isolated package sublayer");
    layer.weight = 0xFFFF;
    rc = FwpmSubLayerAdd0(engine, &layer, nullptr);
    std::printf("WFP_SUBLAYER_ADD=%lu\n", rc);
    require(rc == ERROR_SUCCESS, "Cannot create temporary WFP sublayer");
    // Both blanket-deny filters MUST be scoped to this exact disposable
    // AppContainer SID. A specific v4 allow for *only* 127.0.0.1:proxyPort
    // is given a higher filter weight in the same sublayer.
    for (const GUID* layerKey : {
      &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6}) {
      FWPM_FILTER_CONDITION0 scope{};
      scope.fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
      scope.matchType = FWP_MATCH_EQUAL;
      scope.conditionValue.type = FWP_SID;
      scope.conditionValue.sid = reinterpret_cast<SID*>(appSid);
      FWPM_FILTER0 deny{};
      deny.displayData.name = const_cast<wchar_t*>(L"RCA CI package deny");
      deny.layerKey = *layerKey;
      deny.subLayerKey = sublayer;
      deny.action.type = FWP_ACTION_BLOCK;
      deny.weight.type = FWP_UINT8;
      deny.weight.uint8 = 5;
      deny.numFilterConditions = 1;
      deny.filterCondition = &scope;
      rc = FwpmFilterAdd0(engine, &deny, nullptr, nullptr);
      std::printf("WFP_DENY_ADD=%lu\n", rc);
      require(rc == ERROR_SUCCESS, "Scoped AppContainer deny filter rejected");
    }
    FWPM_FILTER_CONDITION0 permitConditions[4]{};
    permitConditions[0].fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
    permitConditions[0].matchType = FWP_MATCH_EQUAL;
    permitConditions[0].conditionValue.type = FWP_SID;
    permitConditions[0].conditionValue.sid = reinterpret_cast<SID*>(appSid);
    permitConditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    permitConditions[1].matchType = FWP_MATCH_EQUAL;
    permitConditions[1].conditionValue.type = FWP_UINT32;
    permitConditions[1].conditionValue.uint32 = 0x7f000001U;
    permitConditions[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    permitConditions[2].matchType = FWP_MATCH_EQUAL;
    permitConditions[2].conditionValue.type = FWP_UINT16;
    permitConditions[2].conditionValue.uint16 = static_cast<UINT16>(allowedPort);
    permitConditions[3].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    permitConditions[3].matchType = FWP_MATCH_EQUAL;
    permitConditions[3].conditionValue.type = FWP_UINT8;
    permitConditions[3].conditionValue.uint8 = IPPROTO_TCP;
    FWPM_FILTER0 permit{};
    permit.displayData.name = const_cast<wchar_t*>(L"RCA CI package proxy-port-only");
    permit.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    permit.subLayerKey = sublayer;
    permit.action.type = FWP_ACTION_PERMIT;
    permit.weight.type = FWP_UINT8;
    permit.weight.uint8 = 15;
    permit.numFilterConditions = 4;
    permit.filterCondition = permitConditions;
    rc = FwpmFilterAdd0(engine, &permit, nullptr, nullptr);
    std::printf("WFP_PERMIT_ADD=%lu\n", rc);
    require(rc == ERROR_SUCCESS, "Scoped proxy port permit filter rejected");
    std::fflush(stdout);
  }
  void closeAndVerify() {
    require(engine != nullptr, "WFP test engine was not created");
    const DWORD rc = FwpmEngineClose0(engine);
    engine = nullptr;
    require(rc == ERROR_SUCCESS, "Cannot close temporary WFP policy session");
    HANDLE inspect = nullptr;
    require(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr,
      &inspect) == ERROR_SUCCESS, "Cannot inspect WFP policy cleanup");
    FWPM_SUBLAYER0* residual = nullptr;
    const DWORD found = FwpmSubLayerGetByKey0(inspect, &sublayer, &residual);
    if (residual) FwpmFreeMemory0(reinterpret_cast<void**>(&residual));
    FwpmEngineClose0(inspect);
    std::printf("WFP_SUBLAYER_AFTER_CLOSE=%lu\n", found);
    require(found == FWP_E_SUBLAYER_NOT_FOUND,
      "Temporary WFP sublayer survived dynamic engine shutdown");
  }
  ~WfpExperiment() { if (engine) FwpmEngineClose0(engine); }
};
static unsigned makeListener(SOCKET& target) {
  target = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  require(target != INVALID_SOCKET, "Disposable local socket creation failed");
  sockaddr_in bindAddr{};
  bindAddr.sin_family = AF_INET;
  bindAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindAddr.sin_port = 0;
  require(bind(target, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) == 0,
    "Disposable local listener bind failed");
  require(listen(target, 4) == 0, "Disposable local listener listen failed");
  int addrSize = sizeof(bindAddr);
  require(getsockname(target, reinterpret_cast<sockaddr*>(&bindAddr), &addrSize) == 0,
    "Cannot read disposable local listener port");
  return ntohs(bindAddr.sin_port);
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
  // A firewall packet drop can leave a synchronous connect blocked beyond
  // the parent's deadline. A bounded nonblocking connect is a real probe:
  // success is verified with SO_ERROR, not merely writable socket readiness.
  u_long nonblocking = 1;
  if (ioctlsocket(client, FIONBIO, &nonblocking) != 0) {
    closesocket(client); WSACleanup(); return 73;
  }
  int status = connect(client, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
  bool connected = (status == 0);
  if (!connected && WSAGetLastError() == WSAEWOULDBLOCK) {
    fd_set writes, errors;
    FD_ZERO(&writes); FD_SET(client, &writes);
    FD_ZERO(&errors); FD_SET(client, &errors);
    timeval wait{2, 0};
    const int ready = select(0, nullptr, &writes, &errors, &wait);
    if (ready == SOCKET_ERROR) {
      closesocket(client); WSACleanup(); return 74;
    }
    if (ready > 0 && FD_ISSET(client, &writes)) {
      int socketError = 1;
      int length = sizeof(socketError);
      if (getsockopt(client, SOL_SOCKET, SO_ERROR,
          reinterpret_cast<char*>(&socketError), &length) != 0) {
        closesocket(client); WSACleanup(); return 75;
      }
      connected = (socketError == 0);
    }
  }
  closesocket(client);
  WSACleanup();
  return connected ? 0 : 42;
}
int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && wcscmp(argv[1], L"--health") == 0) return 0;
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
  SOCKET other = INVALID_SOCKET;
  try {
    const unsigned port = makeListener(listener);
    const unsigned otherPort = makeListener(other);
    require(port != otherPort, "CI proxy and denied test ports overlapped");
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
    // First prove that the AppContainer can load and execute this exact
    // program without any Winsock calls. A network timeout is not evidence
    // of isolation if a no-network child never reaches main().
    std::puts("APPCONTAINER_SANDBOX_HEALTH_START");
    std::fflush(stdout);
    require(launch(exe, port, profile.sid, true) == 0,
      "AppContainer no-network child did not complete startup");
    std::puts("APPCONTAINER_SANDBOX_START");
    std::fflush(stdout);
    const DWORD result = launch(exe, port, profile.sid);
    std::printf("APPCONTAINER_CHILD_EXIT=%lu\n", result);
    require(result == 42,
      "AppContainer child did not run or failed to deny TCP loopback");
    require(!arrived(listener, 200000),
      "AppContainer made a prohibited direct TCP loopback connection");
    std::puts("WINDOWS_APPCONTAINER_DEFAULT_LOOPBACK=PASS");
    // Keep the parent listener running while the exact ephemeral package
    // receives one allowed proxy-port exception and all-sockets deny.
    {
      WfpExperiment scoped(profile.sid, port);
      require(launch(exe, otherPort, nullptr) == 0,
        "WFP package rule unexpectedly blocked an unrestricted normal process");
      require(arrived(other, 200000),
        "Unrestricted normal process positive-control disappeared");
      const DWORD forbidden = launch(exe, otherPort, profile.sid);
      require(forbidden == 42 && !arrived(other, 200000),
        "WFP scoped rule did not deny neighboring loopback port");
      std::puts("WFP_OTHER_LOOPBACK_PORT_DENIED=PASS");
      const DWORD allowed = launch(exe, port, profile.sid);
      std::printf("WFP_APPCONTAINER_PROXY_PORT_CHILD_EXIT=%lu\n", allowed);
      const bool allowedArrived = arrived(listener, 200000);
      std::printf("WFP_APPCONTAINER_PROXY_PORT_LISTENER_HIT=%d\n",
        static_cast<int>(allowedArrived));
      require(allowed == 0 && allowedArrived,
        "WFP permit did not enable the AppContainer's exact proxy port");
      scoped.closeAndVerify();
    }
    require(launch(exe, port, profile.sid) == 42 && !arrived(listener, 200000),
      "AppContainer could still use proxy after temporary WFP session closed");
    std::puts("WINDOWS_WFP_TEMPORARY_POLICY_CLEANUP=PASS");
    std::puts("WINDOWS_APPCONTAINER_PROXY_ONLY_ISOLATION=FIXTURE_PASS");
  } catch (const std::exception& error) {
    std::fprintf(stderr, "APPCONTAINER_PROBE_ERROR=%s\n", error.what());
    if (listener != INVALID_SOCKET) closesocket(listener);
    if (other != INVALID_SOCKET) closesocket(other);
    WSACleanup();
    return 1;
  }
  closesocket(listener);
  closesocket(other);
  WSACleanup();
  return 0;
}
