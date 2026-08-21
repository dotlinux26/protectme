#pragma once

#include <string>
#include <vector>

namespace protectme::cli {

struct Config {
    std::string command;
    std::string path;
    std::string mode = "DENY";
    bool list = false;
    bool status = false;
    bool remove = false;
    bool help = false;
};

Config parse_args(int argc, char* argv[]);
int run(const Config& config);

} // namespace protectme::cli