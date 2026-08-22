#include "policy.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

namespace protectme::policy {

bool PolicyManager::load(const std::string& file) {
    std::ifstream in(file);
    if (!in) {
        return true;  // Empty policy is valid
    }
    
    entries_.clear();
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        std::istringstream iss(line);
        std::string path_str, mode;
        if (iss >> path_str >> mode) {
            entries_.push_back({std::filesystem::path(path_str), mode});
        } else if (iss >> path_str) {
            entries_.push_back({std::filesystem::path(path_str), "DENY"});
        }
    }
    return true;
}

bool PolicyManager::save(const std::string& file) const {
    std::ofstream out(file);
    if (!out) {
        return false;
    }
    
    for (const auto& entry : entries_) {
        out << entry.path.string() << " " << entry.mode << "\n";
    }
    return true;
}

bool PolicyManager::add(const std::filesystem::path& path, const std::string& mode) {
    auto canonical = std::filesystem::canonical(path);
    
    // Check if already exists
    for (auto& entry : entries_) {
        if (entry.path == canonical) {
            entry.mode = mode;
            return save();
        }
    }
    
    entries_.push_back({canonical, mode});
    return save();
}

bool PolicyManager::remove(const std::filesystem::path& path) {
    auto canonical = std::filesystem::canonical(path);
    
    auto it = std::remove_if(entries_.begin(), entries_.end(),
        [&canonical](const PolicyEntry& e) { return e.path == canonical; });
    
    if (it == entries_.end()) {
        return false;
    }
    
    entries_.erase(it, entries_.end());
    return save();
}

std::vector<PolicyEntry> PolicyManager::list() const {
    return entries_;
}

} // namespace protectme::policy