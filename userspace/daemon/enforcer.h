#pragma once

#include <string>

namespace protectme::daemon {

enum class Action {
    ALLOW,
    DENY,
    QUARANTINE
};

class Enforcer {
public:
    Enforcer() = default;
    
    Action check_operation(const std::string& operation, const std::string& path);
    bool is_protected_root(const std::string& path) const;
    bool is_descendant_of_protected(const std::string& path) const;
    
private:
    // TODO: Protected paths loaded from policy
};

} // namespace protectme::daemon