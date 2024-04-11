#include "UserSpaceRulesRepresentation.hpp"

#include <string.h>

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