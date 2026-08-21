#include "cli/cli.h"
#include "daemon/daemon.h"
#include <iostream>
#include <unistd.h>

int main(int argc, char* argv[]) {
    // Check if running as daemon (no args or special flag)
    if (argc == 1) {
        std::cerr << "Usage: protectme <command> [options]\n";
        std::cerr << "Try 'protectme --help' for more information.\n";
        return 1;
    }
    
    // Check for daemon mode
    if (std::string(argv[1]) == "--daemon") {
        if (geteuid() != 0) {
            std::cerr << "Error: daemon mode requires root\n";
            return 1;
        }
        
        protectme::daemon::Daemon daemon;
        return daemon.start() ? 0 : 1;
    }
    
    // CLI mode
    auto config = protectme::cli::parse_args(argc, argv);
    return protectme::cli::run(config);
}