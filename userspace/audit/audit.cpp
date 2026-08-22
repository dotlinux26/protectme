#include "audit.h"
#include <fstream>
#include <iomanip>
#include <iostream>

namespace protectme::audit {

AuditLogger::AuditLogger(const std::string& file) : log_file_(file) {
    log_stream_.open(log_file_, std::ios::app);
}

AuditLogger::~AuditLogger() {
    if (log_stream_.is_open()) {
        log_stream_.close();
    }
}

bool AuditLogger::log(const AuditEntry& entry) {
    if (!log_stream_.is_open()) {
        return false;
    }
    
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto tm = *std::localtime(&time_t);
    
    log_stream_ << std::put_time(&tm, "%H:%M:%S")
                << " " << entry.action
                << " " << entry.operation
                << " " << entry.path;
    
    if (!entry.reason.empty()) {
        log_stream_ << " " << entry.reason;
    }
    log_stream_ << "\n";
    log_stream_.flush();
    
    return true;
}

bool AuditLogger::log_denied(const std::string& operation, const std::string& path, const std::string& reason) {
    AuditEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.action = "DENY";
    entry.operation = operation;
    entry.path = path;
    entry.reason = reason;
    return log(entry);
}

bool AuditLogger::log_allowed(const std::string& operation, const std::string& path) {
    AuditEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.action = "ALLOW";
    entry.operation = operation;
    entry.path = path;
    return log(entry);
}

} // namespace protectme::audit