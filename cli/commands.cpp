#include "commands.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>

namespace protectme::cli {

constexpr const char* POLICY_FILE = "/etc/protectme/protected";

int cmd_protect(const std::string& path, const std::string& mode) {
    std::filesystem::path p(path);
    auto canonical = std::filesystem::canonical(p);
    
    std::ofstream policy(POLICY_FILE, std::ios::app);
    if (!policy) {
        std::cerr << "Error: cannot open policy file (need root?)\n";
        return 1;
    }
    
    policy << canonical.string() << " " << mode << "\n";
    std::cout << "Protected: " << canonical.string() << " [" << mode << "]\n";
    return 0;
}

int cmd_unprotect(const std::string& path) {
    std::filesystem::path p(path);
    auto canonical = std::filesystem::canonical(p);
    
    std::ifstream in(POLICY_FILE);
    if (!in) {
        std::cerr << "Error: no policy file found\n";
        return 1;
    }
    
    std::string line;
    std::vector<std::string> lines;
    bool found = false;
    
    while (std::getline(in, line)) {
        if (line.rfind(canonical.string() + " ", 0) == 0) {
            found = true;
            continue;
        }
        lines.push_back(line);
    }
    
    if (!found) {
        std::cerr << "Path not in protected list: " << canonical.string() << "\n";
        return 1;
    }
    
    std::ofstream out(POLICY_FILE);
    for (const auto& l : lines) {
        out << l << "\n";
    }
    
    std::cout << "Unprotected: " << canonical.string() << "\n";
    return 0;
}

int cmd_list() {
    std::ifstream in(POLICY_FILE);
    if (!in) {
        std::cout << "No protected paths\n";
        return 0;
    }
    
    std::string line;
    std::cout << "Protected paths:\n";
    while (std::getline(in, line)) {
        std::cout << "  " << line << "\n";
    }
    return 0;
}

int cmd_status() {
    std::cout << "protectme status: not implemented (daemon not running)\n";
    return 0;
}

int cmd_help() {
    std::cout << R"(protectme - kernel-level filesystem safety interlock

Usage:
  protectme <path>              Protect a path (default mode: DENY)
  protectme <path> --mode=MODE  Protect with mode (DENY|QUARANTINE)
  protectme --list              List protected paths
  protectme --remove <path>     Unprotect a path
  protectme --status            Show daemon status
  protectme --help              Show this help

Modes:
  DENY       - Block destructive operations on protected root
  QUARANTINE - Allow deletion but quarantine for 24h (not implemented)

Examples:
  protectme ~/project
  protectme ~/data --mode=DENY
  protectme --list
  protectme --remove ~/old-project
)";
    return 0;
}

} // namespace protectme::cli