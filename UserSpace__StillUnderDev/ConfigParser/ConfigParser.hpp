#pragma once

#include "../rapidjson/document.h"
#include "../../IoctlContracts.h"

#include <vector>

class ConfigParser
{
public:
    std::pair<std::vector<rule>, std::vector<std::string>> get_objects_from_json_file(const std::string& file_path);

private:

    bool validate_json(const rapidjson::Document& doc);

    std::vector<rule> create_rules(const rapidjson::Document& doc);

    std::vector<std::string> create_exclusions(const rapidjson::Document& doc);
};

