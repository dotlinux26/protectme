#pragma once

#include <string>
#include <vector>

namespace protectme::daemon {

struct ProtectedEntry {
    std::string path;
    std::string mode;  // DENY, QUARANTINE
};

class Daemon {
public:
    Daemon();
    ~Daemon();
    
    bool load_policy();
    bool start();
    void stop();
    
private:
    std::vector<ProtectedEntry> protected_paths_;
    bool running_ = false;
};

} // namespace protectme::daemon