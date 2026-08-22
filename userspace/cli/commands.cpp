#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <cstdlib>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/prctl.h>
#include <cstdint>
#include <cstring>
#include <unistd.h>

namespace protectme::cli {

constexpr const char* POLICY_FILE = "/etc/protectme/policy";
constexpr const char* SOCKET_PATH = "/run/protectme/tx.sock";

// Control plane magic numbers (must match loader)
constexpr uint32_t CTL_PROTECT_MAGIC   = 0x50525443u; /* "PRTC" */
constexpr uint32_t CTL_UNPROTECT_MAGIC = 0x55505254u; /* "UPRT" */
constexpr uint32_t CTL_MODE_MAGIC      = 0x4D4F4445u; /* "MODE" */
constexpr uint32_t CTL_RELOAD_MAGIC    = 0x52454C44u; /* "RELD" */

struct ctl_req {
    uint32_t magic;
    uint32_t pid;
    uint32_t dev;
    uint32_t ino;
    uint32_t type;      // TREE=1, FILE=2
    uint32_t owner_uid;
    uint32_t mode;
    uint32_t padding[2];
};

struct ctl_resp {
    int32_t result;
    uint64_t nonce;
};

static bool stat_root(const std::string& path, uint32_t* dev, uint32_t* ino) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    *dev = st.st_dev;
    *ino = st.st_ino;
    return true;
}

static int socket_connect() {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, "/run/protectme/tx.sock", sizeof(sa.sun_path) - 1);
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_ctl_req(uint32_t magic, uint32_t dev, uint32_t ino, uint32_t type) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, "/run/protectme/tx.sock", sizeof(sa.sun_path) - 1);
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    struct ctl_req req = { magic, static_cast<uint32_t>(getpid()), dev, ino, type, 0, 0, {0, 0} };
    if (send(fd, &req, sizeof(req), 0) != sizeof(req)) {
        perror("send");
        close(fd);
        return 1;
    }

    struct ctl_resp resp;
    ssize_t n = recv(fd, &resp, sizeof(resp), 0);
    close(fd);
    if (n != sizeof(resp)) {
        std::cerr << "Error: no response from daemon\n";
        return 1;
    }
    return resp.result == 0 ? 0 : 1;
}

int cmd_protect(const std::string& path, const std::string& /*mode_str*/) {
    std::filesystem::path p(path);
    std::string canonical;
    try {
        canonical = std::filesystem::canonical(path).string();
    } catch (...) {
        std::cerr << "Error: invalid path: " << path << "\n";
        return 1;
    }

    uint32_t dev, ino;
    if (!stat_root(canonical, &dev, &ino)) {
        std::cerr << "Error: cannot stat: " << canonical << "\n";
        return 1;
    }

    // Check if it's a directory or file
    struct stat st;
    stat(canonical.c_str(), &st);
    uint32_t type = S_ISDIR(st.st_mode) ? 1 : 2;  // 1=TREE, 2=FILE

    // Write to policy file (root required)
    std::ofstream policy("/etc/protectme/policy", std::ios::app);
    if (!policy) {
        std::cerr << "Error: cannot open policy file (need root?)\n";
        return 1;
    }
    const char* type_str = (type == 1) ? "TREE" : "FILE";
    policy << type_str << " " << canonical << "\n";
    std::cout << "Protected: " << canonical << " [" << type_str << "]\n";

    // Register in kernel via socket
    if (send_ctl_req(CTL_PROTECT_MAGIC, dev, ino, type) != 0) {
        return 1;
    }
    return 0;
}

int cmd_unprotect(const std::string& path) {
    std::string canonical;
    try {
        canonical = std::filesystem::canonical(path).string();
    } catch (...) {
        std::cerr << "Error: invalid path: " << path << "\n";
        return 1;
    }

    uint32_t dev, ino;
    if (!stat_root(canonical, &dev, &ino)) {
        std::cerr << "Error: cannot stat: " << canonical << "\n";
        return 1;
    }

    // Remove from policy file
    std::ifstream in("/etc/protectme/policy");
    if (!in) {
        std::cerr << "Error: no policy file found\n";
        return 1;
    }

    std::string line;
    std::vector<std::string> lines;
    bool found = false;

    while (std::getline(in, line)) {
        // Check if line contains our path (after TREE/FILE)
        if (line.rfind("TREE " + canonical + " ", 0) == 0 ||
            line.rfind("TREE " + canonical, 0) == 0 ||
            line.rfind("FILE " + canonical + " ", 0) == 0 ||
            line.rfind("FILE " + canonical, 0) == 0) {
            found = true;
            continue;
        }
        lines.push_back(line);
    }

    if (!found) {
        std::cerr << "Path not in protected list: " << canonical << "\n";
        return 1;
    }

    std::ofstream out("/etc/protectme/policy");
    for (const auto& l : lines) {
        out << l << "\n";
    }

    // Unregister in kernel via socket
    if (send_ctl_req(CTL_UNPROTECT_MAGIC, dev, ino, 0) != 0) {
        return 1;
    }

    std::cout << "Unprotected: " << canonical << "\n";
    return 0;
}

int cmd_list() {
    std::ifstream in("/etc/protectme/policy");
    if (!in) {
        std::cout << "No protected paths\n";
        return 0;
    }

    std::string line;
    std::cout << "Protected paths:\n";
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::cout << "  " << line << "\n";
    }
    return 0;
}

int cmd_status() {
    int fd = socket_connect();
    if (fd < 0) {
        std::cout << "STATE=DEAD (daemon unreachable)\n";
        return 1;
    }

    // Send a simple ping or just check state file
    close(fd);

    std::ifstream state("/run/protectme/state");
    if (!state) {
        std::cout << "STATE=DEAD (no state file)\n";
        return 1;
    }

    std::string line, state_val = "UNKNOWN";
    long tm = 0;
    while (std::getline(state, line)) {
        if (line.rfind("STATE=", 0) == 0) state_val = line.substr(6);
        if (line.rfind("time=", 0) == 0) tm = std::stol(line.substr(5));
    }

    long now = time(nullptr);
    bool fresh = (now - tm) < 5;
    std::cout << "STATE=" << state_val << " (" << (fresh ? "ACTIVE" : "STALE/DEAD") << ", age=" << (now - tm) << "s)\n";
    return fresh && state_val == "ACTIVE" ? 0 : 1;
}

int cmd_reload() {
    // Reload policy via socket
    
    if (send_ctl_req(CTL_RELOAD_MAGIC, 0, 0, 0) != 0) {
        return 1;
    }
    return 0;
}

int cmd_help() {
    std::cout << R"(protectme - kernel-level filesystem safety interlock

Usage:
  protectme <path>              Protect a path (tree or file)
  protectme -u <path>           Unprotect a path
  protectme -l                  List protected paths
  protectme -s                  Show daemon status
  protectme -r                  Reload policy (SIGHUP)

Examples:
  protectme ~/project              # Protect a directory
  protectme /etc/secret.key        # Protect a file
  protectme -u ~/project           # Unprotect
  protectme -l                     # List protected
  protectme -s                     # Daemon status
  protectme -r                     # Reload policy

Notes:
  - Normal operations (create, write, rename within, hardlink) always ALLOWED
  - Destructive traversal (rm -rf, find -delete, shutil.rmtree, mv out) DENIED without capability
  - Policy file: /etc/protectme/policy
  - Daemon: systemctl start protectmed
  - v0.1.0: authorized destruction (destroy subcommand) deferred to v0.2
)";
    return 0;
}

} // namespace protectme::cli