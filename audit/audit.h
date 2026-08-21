#pragma once

#include <string>
#include <chrono>
#include <fstream>

namespace protectme::audit {

struct AuditEntry {
    std::chrono::system_clock::time_point timestamp;
    std::string action;      // ALLOW, DENY, QUARANTINE
    std::string operation;   // unlink, rmdir, rename, etc.
    std::string path;
    std::string reason;
};

class AuditLogger {
public:
    static constexpr const char* DEFAULT_LOG_FILE = "/var/log/protectme/audit.log";
    
    explicit AuditLogger(const std::string& file = DEFAULT_LOG_FILE);
    ~AuditLogger();
    
    bool log(const AuditEntry& entry);
    bool log_denied(const std::string& operation, const std::string& path, const std::string& reason);
    bool log_allowed(const std::string& operation, const std::string& path);
    
private:
    std::string log_file_;
    std::ofstream log_stream_;
};

} // namespace protectme::audit