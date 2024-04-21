#pragma once

#include "../Kernel/IoctlContracts.h"

#include <string>

struct userspace_execve_rule
{
    execve_rule to_execve_rule();

    std::string binary_path;
    std::string full_command;
    int uid;
    int gid;
    int argc;
    int prevention;
};

struct userspace_open_rule
{
    open_rule to_open_rule();

    std::string binary_path;
    std::string full_command;
    std::string target_path;
    int uid;
    int gid;
    int flags;
    int mode;
    int prevention;
};