#include "UserSpaceRulesRepresentation.hpp"

#include <iostream>
#include <string.h>

void userspace_rule::set_value_via_cli(int& value, const int& default_value)
{
    std::string line;
    std::getline(std::cin, line);
    try
    {
        value = line.empty() ? default_value : std::stoi(line);
    }
    catch(const std::exception& e)
    {
        std::cout << "Invalid input. Using default value: " << default_value << std::endl;
        value = default_value;
    }
}

void userspace_rule::set_string_via_cli(std::string& value, std::string&& default_value)
{
    std::getline(std::cin, value);
    value = value.empty() ? default_value : value;
}


execve_event userspace_execve_rule::build_rule_via_cli()
{
    std::cout << "Binary path: ";
    set_string_via_cli(binary_path, DEFAULT_BINARY_PATH);
    std::cout << "Full command: ";
    set_string_via_cli(full_command, DEFAULT_FULL_COMMAND);
    std::cout << "UID: ";
    set_value_via_cli(uid, DEFAULT_UID);
    std::cout << "GID: ";
    set_value_via_cli(gid, DEFAULT_GID);
    std::cout << "Argc: ";
    set_value_via_cli(argc, DEFAULT_ARGC);
    std::cout << "Prevention: ";
    set_value_via_cli(prevention, DEFAULT_PREVENTION);
    return to_execve_rule();
}

execve_rule userspace_execve_rule::to_execve_rule()
{
    execve_rule rule = {};
    strncpy(rule.binary_path, binary_path.c_str(), sizeof(rule.full_command));
    strncpy(rule.full_command, full_command.c_str(), sizeof(rule.full_command));
    rule.uid = uid;
    rule.gid = gid;
    rule.argc = argc;
    rule.prevention = prevention;
    return rule;
}

open_event userspace_open_rule::build_rule_via_cli()
{
    std::cout << "Binary path: ";
    set_string_via_cli(binary_path, DEFAULT_BINARY_PATH);
    std::cout << "Full command: ";
    set_string_via_cli(full_command, DEFAULT_FULL_COMMAND);
    std::cout << "Target path: ";
    set_string_via_cli(target_path, DEFAULT_TARGET_PATH);
    std::cout << "UID: ";
    set_value_via_cli(uid, DEFAULT_UID);
    std::cout << "GID: ";
    set_value_via_cli(gid, DEFAULT_GID);
    std::cout << "Flags: ";
    set_value_via_cli(flags, DEFAULT_FLAGS);
    std::cout << "Mode: ";
    set_value_via_cli(mode, DEFAULT_MODE);
    std::cout << "Prevention: ";
    set_value_via_cli(prevention, DEFAULT_PREVENTION);
    return to_open_rule();
}

open_rule userspace_open_rule::to_open_rule()
{
    open_rule rule = {};
    strncpy(rule.binary_path, binary_path.c_str(), sizeof(rule.binary_path));
    strncpy(rule.full_command, full_command.c_str(), sizeof(rule.full_command));
    strncpy(rule.target_path, target_path.c_str(), sizeof(rule.target_path));
    rule.uid = uid;
    rule.gid = gid;
    rule.flags = flags;
    rule.mode = mode;
    rule.prevention = prevention;
    return rule;
}