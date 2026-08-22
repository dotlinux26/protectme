#include "cli.h"
#include "commands.h"
#include <iostream>
#include <string>
#include <vector>

namespace protectme::cli {

Config parse_args(int argc, char* argv[]) {
    Config config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-l" || arg == "--list") {
            config.list = true;
        } else if (arg == "-s" || arg == "--status") {
            config.status = true;
        } else if (arg == "-r" || arg == "--reload") {
            config.reload = true;
        } else if (arg == "-u" || arg == "--unprotect") {
            config.unprotect = true;
        } else if (arg == "-h" || arg == "--help") {
            config.help = true;
        } else if (arg == "destroy") {
            config.command = "destroy";
            // Collect remaining args for destroy
            for (int j = i + 1; j < argc; ++j) {
                config.destroy_args.push_back(argv[j]);
            }
            break;
        } else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            config.help = true;
        } else {
            if (config.path.empty()) {
                config.path = arg;
            }
        }
    }
    
    // Determine command
    if (config.help || (config.path.empty() && !config.list && !config.status && !config.reload && !config.unprotect && config.destroy_args.empty())) {
        config.help = true;
    } else if (config.unprotect) {
        config.command = "unprotect";
    } else if (config.list) {
        config.command = "list";
    } else if (config.status) {
        config.command = "status";
    } else if (config.reload) {
        config.command = "reload";
    } else if (!config.path.empty() && config.command.empty()) {
        config.command = "protect";
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
    
    if (config.reload) {
        return cmd_reload();
    }
    
    if (config.unprotect) {
        if (config.path.empty()) {
            std::cerr << "Error: path required for -u\n";
            return 1;
        }
        return cmd_unprotect(config.path);
    }
    
    if (!config.destroy_args.empty()) {
        // Reconstruct argv for destroy
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("protectme"));
        argv.push_back(const_cast<char*>("destroy"));
        for (const auto& arg : config.destroy_args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);
        return cmd_destroy(argv.size() - 1, argv.data());
    }
    
    if (config.command == "protect") {
        if (config.path.empty()) {
            std::cerr << "Error: path required\n";
            return 1;
        }
        return cmd_protect(config.path, config.mode);
    }
    
    std::cerr << "Error: unknown command\n";
    return 1;
}

} // namespace protectme::cli