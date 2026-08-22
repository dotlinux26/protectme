#include "commands.h"
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

namespace protectme::cli {

constexpr const char* POLICY_FILE = "/etc/protectme/policy";
constexpr const char* SOCKET_PATH = "/run/protectme/tx.sock";

// Prctl magic numbers (must match kernel)
constexpr uint32_t PM_INODE_SET_MAGIC = 0x494E4F44;  // "INOD"
constexpr uint32_t PM_INODE_DEL_MAGIC = 0x44454C49;  // "DELI"
constexpr uint32_t PM_MODE_SET_MAGIC  = 0x4D4F4445;  // "MODE"
constexpr uint32_t PM_TX_REVOKE_MAGIC = 0x52564B45;  // "RVKE"
constexpr uint32_t CAP_REQ_MAGIC = 0x34424D50;       // "PMB4"
constexpr uint32_t CAP_REV_MAGIC = 0x34424D35;       // "PMB5"

struct cap_req {
    uint32_t magic;
    uint32_t pid;
    uint32_t dev;
    uint32_t ino;
    uint32_t ttl_ms;
};

struct cap_resp {
    uint64_t nonce;
};

static int syscall_prctl(uint32_t op, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4) {
    return syscall(SYS_prctl, op, a1, a2, a3, a4);
}

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
    const char* type = S_ISDIR(st.st_mode) ? "TREE" : "FILE";

    // Write to policy file (root required)
    std::ofstream policy("/etc/protectme/policy", std::ios::app);
    if (!policy) {
        std::cerr << "Error: cannot open policy file (need root?)\n";
        return 1;
    }
    policy << type << " " << canonical << "\n";
    std::cout << "Protected: " << canonical << " [" << type << "]\n";

    // Also register in kernel immediately via prctl
    syscall_prctl(PM_INODE_SET_MAGIC, dev, ino, 0xFEEDFACE, 0);
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

    // Also unregister in kernel
    syscall_prctl(PM_INODE_DEL_MAGIC, dev, ino, 0, 0);

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
    // Use systemctl reload for systemd-managed daemon
    if (system("systemctl reload protectmed") != 0) {
        std::cerr << "Error: failed to reload policy (systemctl reload protectmed)\n";
        return 1;
    }
    std::cout << "Policy reload triggered\n";
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