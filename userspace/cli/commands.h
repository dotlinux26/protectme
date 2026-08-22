#ifndef PROTECTME_CLI_COMMANDS_H
#define PROTECTME_CLI_COMMANDS_H

#include <string>

namespace protectme::cli {

int cmd_protect(const std::string& path, const std::string& mode = "");
int cmd_unprotect(const std::string& path);
int cmd_list();
int cmd_status();
int cmd_reload();
int cmd_destroy(int argc, char* argv[]);
int cmd_help();

} // namespace protectme::cli

#endif // PROTECTME_CLI_COMMANDS_H