#pragma once

#include "../rapidjson/document.h"
#include "../../IoctlContracts.h"

#include <vector>

struct userspace_execve_rule
{
    // execve_event build_rule_via_cli()
    // {
    //     clear();
    //     std::cout << "Enter binary path: ";
    //     std::cin >> binary_path;

    //     std::cout << "Enter full command: ";
    // }

    void clear()
    {
        binary_path.clear();
        full_command.clear();
        uid = 0;
        gid = 0;
        argc = 0;
        prevention = 0;
    }

    execve_rule to_execve_rule()
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

    std::string binary_path;
    std::string full_command;
    int uid;
    int gid;
    int argc;
    int prevention;
};

struct userspace_open_rule
{
    open_rule to_open_rule()
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

    std::string binary_path;
    std::string full_command;
    std::string target_path;
    int uid;
    int gid;
    int flags;
    int mode;
    int prevention;
};

class ConfigParser
{
public:
    std::pair<std::vector<rule>, std::vector<std::string>> get_objects_from_json_file(const std::string& file_path);

private:

    bool validate_json(const rapidjson::Document& doc);

    std::vector<rule> create_rules(const rapidjson::Document& doc);

    std::vector<std::string> create_exclusions(const rapidjson::Document& doc);
};

