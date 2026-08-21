#pragma once

#include <string>
#include <vector>
#include <filesystem>

namespace protectme::policy {

struct PolicyEntry {
    std::filesystem::path path;
    std::string mode = "DENY";
};

class PolicyManager {
public:
    static constexpr const char* DEFAULT_POLICY_FILE = "/etc/protectme/protected";
    
    bool load(const std::string& file = DEFAULT_POLICY_FILE);
    bool save(const std::string& file = DEFAULT_POLICY_FILE) const;
    
    bool add(const std::filesystem::path& path, const std::string& mode = "DENY");
    bool remove(const std::filesystem::path& path);
    std::vector<PolicyEntry> list() const;
    
private:
    std::vector<PolicyEntry> entries_;
};

} // namespace protectme::policy