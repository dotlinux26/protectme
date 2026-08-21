#include "cli.h"
#include "commands.h"
#include <iostream>
#include <filesystem>

namespace protectme::cli {

Config parse_args(int argc, char* argv[]) {
    Config config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--list" || arg == "-l") {
            config.list = true;
        } else if (arg == "--status" || arg == "-s") {
            config.status = true;
        } else if (arg == "--remove" || arg == "-r") {
            config.remove = true;
        } else if (arg == "--help" || arg == "-h") {
            config.help = true;
        } else if (arg.rfind("--mode=", 0) == 0) {
            config.mode = arg.substr(7);
        } else if (arg[0] != '-') {
            if (config.command.empty()) {
                config.command = arg;
            } else if (config.path.empty()) {
                config.path = arg;
            }
        }
    }
    
    if (config.help || (config.command.empty() && !config.list && !config.status)) {
        config.help = true;
    }
    
    return config;
}

int run(const Config& config) {
    if (config.help) {
        return cmd_help();
    }
    
    if (config.list) {
        return cmd_list();
    }
    
    if (config.status) {
        return cmd_status();
    }
    
    if (config.remove) {
        if (config.path.empty()) {
            std::cerr << "Error: path required for --remove\n";
            return 1;
        }
        return cmd_unprotect(config.path);
    }
    
    if (config.command == "protect") {
        if (config.path.empty()) {
            std::cerr << "Error: path required for protect\n";
            return 1;
        }
        return cmd_protect(config.path, config.mode);
    }
    
    std::cerr << "Error: unknown command: " << config.command << "\n";
    return 1;
}

} // namespace protectme::cli