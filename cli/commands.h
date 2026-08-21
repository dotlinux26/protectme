#pragma once

#include <string>

namespace protectme::cli {

int cmd_protect(const std::string& path, const std::string& mode);
int cmd_unprotect(const std::string& path);
int cmd_list();
int cmd_status();
int cmd_help();

} // namespace protectme::cli