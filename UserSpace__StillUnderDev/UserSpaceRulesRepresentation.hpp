#pragma once

#include "../Kernel/IoctlContracts.h"

#include <string>

class userspace_rule
{
protected:
    virtual ~userspace_rule() = default;

    void set_value_via_cli(int& value, const int& default_value);

    void set_string_via_cli(std::string& value, std::string&& default_value);
};

class userspace_execve_rule : public userspace_rule
{
public:
    execve_event build_rule_via_cli();

    execve_rule to_execve_rule();

    std::string binary_path;
    std::string full_command;
    int uid;
    int gid;
    int argc;
    int prevention;
};

class userspace_open_rule : public userspace_rule
{
public:
    open_event build_rule_via_cli();

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