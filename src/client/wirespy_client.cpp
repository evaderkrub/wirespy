// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// wirespy_client.cpp -- see wirespy_client.h.
#include "wirespy_client.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
using sock_t = SOCKET;
static constexpr sock_t kBadSock = INVALID_SOCKET;
static void close_sock(sock_t s) { closesocket(s); }
static constexpr int kSendFlags = 0;
static void winsock_init() { static bool once = false; if (!once) { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); once = true; } }
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
using sock_t = int;
static constexpr sock_t kBadSock = -1;
static void close_sock(sock_t s) { ::close(s); }
static constexpr int kSendFlags = MSG_NOSIGNAL;
static void winsock_init() {}
#endif

namespace wirespy {

// ---------------------------------------------------------------------------
// WirespyClient
// ---------------------------------------------------------------------------
WirespyClient::WirespyClient() { winsock_init(); }
WirespyClient::~WirespyClient() { close(); }

void WirespyClient::close() {
    if (sock_ >= 0) close_sock((sock_t)sock_);
    sock_ = -1;
}

bool WirespyClient::connect(const std::string& host, std::uint16_t port, std::string& error) {
    close();
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == kBadSock) { error = "socket() failed"; return false; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) { close_sock(s); error = "bad host"; return false; }
    if (::connect(s, (sockaddr*)&addr, sizeof addr) != 0) {
        close_sock(s);
        error = "cannot connect to " + host + ":" + std::to_string(port);
        return false;
    }
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof one);
    sock_ = (long long)s;
    return true;
}

static bool write_all(sock_t s, const std::uint8_t* p, std::size_t n) {
    while (n > 0) {
        const int r = send(s, (const char*)p, (int)n, kSendFlags);
        if (r <= 0) return false;
        p += r; n -= (std::size_t)r;
    }
    return true;
}
static bool read_exact(sock_t s, std::uint8_t* p, std::size_t n) {
    while (n > 0) {
        const int r = recv(s, (char*)p, (int)n, 0);
        if (r <= 0) return false;
        p += r; n -= (std::size_t)r;
    }
    return true;
}

bool WirespyClient::send_request(const nlohmann::json& header, std::span<const std::uint8_t> frame, std::string& error) {
    if (sock_ < 0) { error = "not connected"; return false; }
    const std::string h = header.dump();
    const std::uint32_t json_len = (std::uint32_t)h.size();
    const std::uint32_t total = 4 + json_len + (std::uint32_t)frame.size();
    std::vector<std::uint8_t> buf;
    buf.reserve(4 + total);
    auto put32 = [&](std::uint32_t v) {
        buf.push_back((std::uint8_t)(v >> 24)); buf.push_back((std::uint8_t)(v >> 16));
        buf.push_back((std::uint8_t)(v >> 8));  buf.push_back((std::uint8_t)v);
    };
    put32(total);
    put32(json_len);
    buf.insert(buf.end(), h.begin(), h.end());
    buf.insert(buf.end(), frame.begin(), frame.end());
    if (!write_all((sock_t)sock_, buf.data(), buf.size())) { error = "connection lost (send)"; close(); return false; }
    return true;
}

bool WirespyClient::read_reply(nlohmann::json& out, std::string& error) {
    if (sock_ < 0) { error = "not connected"; return false; }
    std::uint8_t lb[4];
    if (!read_exact((sock_t)sock_, lb, 4)) { error = "connection lost (recv)"; close(); return false; }
    const std::uint32_t len = ((std::uint32_t)lb[0] << 24) | ((std::uint32_t)lb[1] << 16) | ((std::uint32_t)lb[2] << 8) | lb[3];
    if (len > 256u * 1024u * 1024u) { error = "reply too large"; close(); return false; }
    std::vector<std::uint8_t> body(len);
    if (len && !read_exact((sock_t)sock_, body.data(), len)) { error = "connection lost (recv body)"; close(); return false; }
    try {
        out = nlohmann::json::parse(body.begin(), body.end());
    } catch (const std::exception& e) {
        error = std::string("bad reply: ") + e.what();
        return false;
    }
    return true;
}

static void ParseTree(const nlohmann::json& j, DetailNode& n) {
    n.name = j.value("name", "");
    n.text = j.value("showname", "");
    n.pos = j.value("pos", 0);
    n.size = j.value("size", 0);
    if (auto it = j.find("children"); it != j.end() && it->is_array()) {
        n.children.reserve(it->size());
        for (const auto& c : *it) { n.children.emplace_back(); ParseTree(c, n.children.back()); }
    }
}

bool WirespyClient::decode(const std::vector<DecodeAsk>& asks, std::vector<DecodeReply>& out, std::string& error) {
    out.clear();
    out.reserve(asks.size());
    int id = 0;
    for (const DecodeAsk& a : asks) {
        nlohmann::json h = {
            {"op", "decode"}, {"id", ++id}, {"link_type", a.dlt},
            {"tree", a.tree}, {"columns", a.columns}, {"color", a.color},
        };
        if (a.has_ts) { h["ts_sec"] = a.ts_sec; h["ts_nsec"] = a.ts_nsec; }
        if (a.transient) {
            h["transient"] = true;
            h["frame_number"] = a.frame_number;
            if (a.has_ref) { h["ref_ts_sec"] = a.ref_ts_sec; h["ref_ts_nsec"] = a.ref_ts_nsec; }
            if (a.has_prev) { h["prev_ts_sec"] = a.prev_ts_sec; h["prev_ts_nsec"] = a.prev_ts_nsec; }
        }
        if (!send_request(h, a.frame, error)) return false;
    }
    for (std::size_t i = 0; i < asks.size(); ++i) {
        nlohmann::json r;
        if (!read_reply(r, error)) return false;
        DecodeReply d;
        d.ok = r.value("ok", false);
        if (!d.ok) {
            if (auto e = r.find("error"); e != r.end()) d.error = e->value("message", "decode failed");
            else d.error = "decode failed";
        } else {
            d.frame_number = r.value("frame_number", 0u);
            d.match = r.value("match", true);
            if (auto c = r.find("columns"); c != r.end() && c->is_array())
                for (const auto& s : *c) d.columns.push_back(s.is_string() ? s.get<std::string>() : std::string());
            if (auto c = r.find("color"); c != r.end() && c->is_object()) {
                d.color_name = c->value("name", "");
                d.color_fg = c->value("fg", "");
                d.color_bg = c->value("bg", "");
            }
            if (auto t = r.find("decode"); t != r.end() && t->is_object()) {
                ParseTree(*t, d.tree);
                d.has_tree = true;
            }
        }
        out.push_back(std::move(d));
    }
    return true;
}

bool WirespyClient::set_filter(const std::string& text, std::string& error) {
    nlohmann::json h = {{"op", "set_filter"}, {"id", 1}, {"filter", text}};
    if (!send_request(h, {}, error)) return false;
    nlohmann::json r;
    if (!read_reply(r, error)) return false;
    if (!r.value("ok", false)) {
        error = r.contains("error") ? r["error"].value("message", "invalid filter") : "invalid filter";
        return false;
    }
    return true;
}

bool WirespyClient::reset(std::string& error) {
    nlohmann::json h = {{"op", "reset"}, {"id", 1}};
    if (!send_request(h, {}, error)) return false;
    nlohmann::json r;
    return read_reply(r, error) && r.value("ok", false);
}

bool WirespyClient::info(nlohmann::json& out, std::string& error) {
    nlohmann::json h = {{"op", "info"}, {"id", 1}};
    if (!send_request(h, {}, error)) return false;
    return read_reply(out, error) && out.value("ok", false);
}

// ---------------------------------------------------------------------------
// ServerLauncher
// ---------------------------------------------------------------------------
std::string ExeDir() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH * 2];
    const DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)(sizeof buf / sizeof buf[0]));
    if (n == 0) return {};
    std::wstring w(buf, n);
    const auto slash = w.find_last_of(L"\\/");
    if (slash != std::wstring::npos) w.resize(slash);
    const int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((std::size_t)len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), len, nullptr, nullptr);
    return s;
#else
    char buf[PATH_MAX];
    const ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) return {};
    std::string s(buf, (std::size_t)n);
    const auto slash = s.find_last_of('/');
    if (slash != std::string::npos) s.resize(slash);
    return s;
#endif
}

static bool FileExists(const std::string& p) {
#ifdef _WIN32
    const DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
#else
    return access(p.c_str(), X_OK) == 0;
#endif
}
static bool DirExists(const std::string& p) {
#ifdef _WIN32
    const DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
#endif
}
static std::string DirOf(const std::string& p) {
    const auto k = p.find_last_of("/\\");
    return k == std::string::npos ? std::string(".") : p.substr(0, k);
}

ServerLauncher::~ServerLauncher() { stop(); }

void ServerLauncher::stop() {
    if (pid_ == 0) return;
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid_);
    if (h) { TerminateProcess(h, 0); CloseHandle(h); }
#else
    ::kill((pid_t)pid_, SIGTERM);
    int st = 0;
    for (int i = 0; i < 20; ++i) {
        if (waitpid((pid_t)pid_, &st, WNOHANG) == (pid_t)pid_) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    ::kill((pid_t)pid_, SIGKILL);
    waitpid((pid_t)pid_, &st, WNOHANG);
#endif
    pid_ = 0;
    port_ = 0;
}

// Parse "wirespy listening on tcp/N" out of what the child printed.
static std::uint16_t PortFromBanner(const std::string& line) {
    const auto k = line.find("tcp/");
    if (k == std::string::npos) return 0;
    return (std::uint16_t)std::atoi(line.c_str() + k + 4);
}

std::uint16_t ServerLauncher::spawn(const std::string& exe, std::string& error) {
    // The MSYS2 staging layout puts Wireshark's data files (colouring rules,
    // filter macros) beside the server; a server built against an installed
    // Wireshark has them compiled in and gets no flag.
    const std::string dir = DirOf(exe);
    const std::string data = dir + "/share/wireshark";
    const bool have_data = DirExists(data);
#ifdef _WIN32
    SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { error = "CreatePipe failed"; return 0; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    std::string cmd = "\"" + exe + "\" --port 0 --parent-pid " + std::to_string(GetCurrentProcessId());
    if (have_data) cmd += " --data-dir \"" + data + "\"";
    std::vector<char> cmdbuf(cmd.begin(), cmd.end());
    cmdbuf.push_back('\0');
    // Working directory = the server's own folder, so the DLLs staged beside
    // it (libwireshark, glib, ...) resolve without touching PATH.
    const BOOL ok = CreateProcessA(nullptr, cmdbuf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                   nullptr, dir.c_str(), &si, &pi);
    CloseHandle(wr);
    if (!ok) { CloseHandle(rd); error = "CreateProcess failed for " + exe; return 0; }
    CloseHandle(pi.hThread);
    pid_ = (long long)pi.dwProcessId;
    std::string line;
    char ch;
    DWORD got = 0;
    while (ReadFile(rd, &ch, 1, &got, nullptr) && got == 1) {
        if (ch == '\n') break;
        line.push_back(ch);
        if (line.size() > 200) break;
    }
    CloseHandle(rd);
    CloseHandle(pi.hProcess);
#else
    int fds[2];
    if (pipe(fds) != 0) { error = "pipe() failed"; return 0; }
    const pid_t pid = fork();
    if (pid < 0) { error = "fork() failed"; ::close(fds[0]); ::close(fds[1]); return 0; }
    if (pid == 0) {
        ::close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        ::close(fds[1]);
        const std::string ppid = std::to_string(getppid());
        if (have_data)
            execl(exe.c_str(), exe.c_str(), "--port", "0", "--parent-pid", ppid.c_str(), "--data-dir", data.c_str(), (char*)nullptr);
        else
            execl(exe.c_str(), exe.c_str(), "--port", "0", "--parent-pid", ppid.c_str(), (char*)nullptr);
        _exit(127);
    }
    ::close(fds[1]);
    pid_ = pid;
    std::string line;
    // The banner arrives once libwireshark has initialised (a second or two
    // the first time the dissector tables are built).
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd p{fds[0], POLLIN, 0};
        const int r = poll(&p, 1, 100);
        if (r < 0) break;
        if (r == 0) {
            int st = 0;
            if (waitpid(pid, &st, WNOHANG) == pid) { pid_ = 0; break; }
            continue;
        }
        char ch;
        const ssize_t n = read(fds[0], &ch, 1);
        if (n <= 0) break;
        if (ch == '\n') break;
        line.push_back(ch);
        if (line.size() > 200) break;
    }
    ::close(fds[0]);
#endif
    port_ = PortFromBanner(line);
    if (port_ == 0) {
        error = "wirespy_server did not announce a port (" + (line.empty() ? std::string("no output") : line) + ")";
        stop();
        return 0;
    }
    desc_ = exe + " (pid " + std::to_string(pid_) + ", port " + std::to_string(port_) + ")";
    return port_;
}

std::uint16_t ServerLauncher::ensure(std::string& error) {
    if (port_ != 0) return port_;
    error.clear();
    std::vector<std::string> candidates = extra_;
    if (const char* env = std::getenv("WIRESPY_SERVER"); env && *env) candidates.emplace_back(env);
    const std::string dir = ExeDir();
    if (!dir.empty()) {
#ifdef _WIN32
        candidates.push_back(dir + "\\wirespy\\wirespy_server.exe");
        candidates.push_back(dir + "\\wirespy_server.exe");
#else
        candidates.push_back(dir + "/wirespy/wirespy_server");
        candidates.push_back(dir + "/wirespy_server");
#endif
    }
    std::string why;
    for (const std::string& c : candidates) {
        if (!FileExists(c)) { why += c + ": not found\n"; continue; }
        std::string e;
        if (const std::uint16_t p = spawn(c, e)) return p;
        why += c + ": " + e + "\n";
    }
    // Last resort: a server somebody started by hand on the default port.
    WirespyClient probe;
    std::string e;
    if (probe.connect("127.0.0.1", 51717, e)) {
        port_ = 51717;
        desc_ = "an already-running wirespy_server on port 51717";
        return port_;
    }
    error = "no wirespy_server: " + why + "and nothing listening on 127.0.0.1:51717";
    return 0;
}

} // namespace wirespy
