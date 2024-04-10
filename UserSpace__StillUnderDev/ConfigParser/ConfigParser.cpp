#include "ConfigParser.hpp"
#include "../rapidjson/schema.h"
#include "../rapidjson/filereadstream.h"
#include "Schema.hpp"
#include "../UserSpaceRulesRepresentation.hpp"

#include <iostream>
#include <fstream>
#include <sstream>

    std::pair<std::vector<rule>, std::vector<std::string>> ConfigParser::get_objects_from_json_file(const std::string& file_path)
    {
        std::fstream configFile(file_path);
        if (!configFile.is_open())
        {
            std::cout << "Failed to open config file" << std::endl;
            return {};
        }

        std::stringstream configBuffer;
        configBuffer << configFile.rdbuf();
        std::string config = configBuffer.str();

        rapidjson::Document doc;
        if (doc.Parse(config.c_str()).HasParseError()) 
        {
            std::cerr << "JSON parse error" << std::endl;
            return {};
        }

        if(!validate_json(doc))
        {
            return {};
        }

        auto rules = create_rules(doc);
        auto exclusions = create_exclusions(doc);

        return {rules, exclusions};
    }

    bool ConfigParser::validate_json(const rapidjson::Document& doc)
    {
        rapidjson::Document schemaDoc;
        if (schemaDoc.Parse(rules_and_exclusions_schema.c_str()).HasParseError()) 
        {
            std::cerr << "Schema parse error" << std::endl;
            return false;
        }

        rapidjson::SchemaDocument schemaDocument(schemaDoc);
        rapidjson::SchemaValidator validator(schemaDocument);

        if(!doc.Accept(validator))
        {
            std::cerr << "Invalid JSON" << std::endl;
            return false;
        }

        return true;
    }

    std::vector<rule> ConfigParser::create_rules(const rapidjson::Document& doc)
    {
        std::vector<rule> rules;

        if (doc.HasMember("execve_rules") && doc["execve_rules"].IsArray()) 
        {
            for (auto& m : doc["execve_rules"].GetArray()) 
            {
                userspace_execve_rule user_rule;
                user_rule.binary_path = m.HasMember("binary_path") ? m["binary_path"].GetString() : DEFAULT_BINARY_PATH;
                user_rule.full_command = m.HasMember("full_command") ? m["full_command"].GetString() : DEFAULT_FULL_COMMAND;
                user_rule.uid = m.HasMember("uid") ? m["uid"].GetInt() : DEFAULT_UID;
                user_rule.gid = m.HasMember("gid") ? m["gid"].GetInt() : DEFAULT_GID;
                user_rule.argc = m.HasMember("argc") ? m["argc"].GetInt() : DEFAULT_ARGC;
                user_rule.prevention = m.HasMember("prevention") ? m["prevention"].GetInt() : DEFAULT_PREVENTION;
                struct rule rule;
                rule.type = execve_rule_type;
                rule.data.execve = user_rule.to_execve_rule();
                rules.push_back(rule);
            }
        }

        if (doc.HasMember("open_rules") && doc["open_rules"].IsArray()) 
        {
            for (auto& m : doc["open_rules"].GetArray()) 
            {
                userspace_open_rule user_rule;
                user_rule.binary_path = m.HasMember("binary_path") ? m["binary_path"].GetString() : DEFAULT_BINARY_PATH;
                user_rule.full_command = m.HasMember("full_command") ? m["full_command"].GetString() : DEFAULT_FULL_COMMAND;
                user_rule.target_path = m.HasMember("target_path") ? m["target_path"].GetString() : DEFAULT_TARGET_PATH;
                user_rule.uid = m.HasMember("uid") ? m["uid"].GetInt() : DEFAULT_UID;
                user_rule.gid = m.HasMember("gid") ? m["gid"].GetInt() : DEFAULT_GID;
                user_rule.flags = m.HasMember("flags") ? m["flags"].GetInt() : DEFAULT_FLAGS;
                user_rule.mode = m.HasMember("mode") ? m["mode"].GetInt() : DEFAULT_MODE;
                user_rule.prevention = m.HasMember("prevention") ? m["prevention"].GetInt() : DEFAULT_PREVENTION;
                struct rule rule;
                rule.type = open_rule_type;
                rule.data.open = user_rule.to_open_rule();
                rules.push_back(rule);
            }
        }

        return rules;
    }

    std::vector<std::string> ConfigParser::create_exclusions(const rapidjson::Document& doc)
    {
        std::vector<std::string> exclusions;

        if (doc.HasMember("excluded_binary_paths") && doc["excluded_binary_paths"].IsArray()) 
        {
            for (auto& m : doc["excluded_binary_paths"].GetArray()) 
            {
                exclusions.push_back(m.GetString());
            }
        }

        return exclusions;
    }
