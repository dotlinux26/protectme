#include "enforcer.h"

namespace protectme::daemon {

Action Enforcer::check_operation(const std::string& /*operation*/, const std::string& /*path*/) {
    // TODO: Implement actual enforcement logic
    // For now, always ALLOW (stub)
    return Action::ALLOW;
}

bool Enforcer::is_protected_root(const std::string& /*path*/) const {
    // TODO: Check against loaded protected roots
    return false;
}

bool Enforcer::is_descendant_of_protected(const std::string& /*path*/) const {
    // TODO: Check if path is inside a protected tree
    return false;
}

} // namespace protectme::daemon