#include "daemon.h"
#include "enforcer.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>

namespace protectme::daemon {

Daemon::Daemon() = default;

Daemon::~Daemon() {
    stop();
}

bool Daemon::load_policy() {
    constexpr const char* POLICY_FILE = "/etc/protectme/protected";
    std::ifstream in(POLICY_FILE);
    if (!in) {
        return true;  // Empty policy is valid
    }
    
    protected_paths_.clear();
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        std::istringstream iss(line);
        std::string path, mode;
        if (iss >> path >> mode) {
            protected_paths_.push_back({path, mode});
        } else if (iss >> path) {
            protected_paths_.push_back({path, "DENY"});
        }
    }
    
    std::cout << "Loaded " << protected_paths_.size() << " protected paths\n";
    return true;
}

bool Daemon::start() {
    if (!load_policy()) {
        return false;
    }
    
    running_ = true;
    std::cout << "protectme daemon started (stub - LSM enforcement not implemented)\n";
    
    // TODO: Initialize LSM/BPF enforcement here
    // For now, just keep running
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return true;
}

void Daemon::stop() {
    running_ = false;
}

} // namespace protectme::daemon