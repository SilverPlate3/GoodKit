#include "Menu.hpp"
#include "ConfigParser/ConfigParser.hpp"
#include "Ioctl.hpp"
#include "UserSpaceRulesRepresentation.hpp"

#include <iostream>
#include <cstdlib>
#include <filesystem>

    void Menu::start() 
    {
        int option;
        displayMenu();
        std::cin >> option;
        std::cout << std::endl;
        processOption(option);
    }

    void Menu::displayMenu() 
    {
        std::cout << "\nSelect an option by typing its number:\n"
                  << "1 - Add multiple rules and exclusions via json\n"
                  << "2 - Add single rule\n"
                  << "3 - Add single exclusion\n"
                  << "4 - Delete all rules\n"
                  << "5 - Delete all exclusions\n"
                  << "6 - Print all rules (dmesg)\n"
                  << "7 - Print all exclusions (dmesg)\n"
                  << "8 - Clear CLI\n"
                  << "Enter your choice: ";
    }

    void Menu::processOption(int option) 
    {
        std::cout << std::endl;
        switch (option) 
        {
            case 1: addMultipleRulesAndExclusions(); break;
            case 2: addSingleRule(); break;
            case 3: addSingleExclusion(); break;
            case 4: deleteAllRules(); break;
            case 5: deleteAllExclusions(); break;
            case 6: printAllRules(); break;
            case 7: printAllExclusions(); break;
            case 8: clearCLI(); break;
            default: std::cout << "Invalid option. Please try again." << std::endl;
        }
    }

    void Menu::addMultipleRulesAndExclusions() 
    {
        std::cout << "Input json path: ";
        std::string jsonPath;
        std::cin >> jsonPath;
        if(!std::filesystem::exists(jsonPath))
        {
            std::cout << "json '" << jsonPath << "' does not exist.\n";
            return;
        }

        ConfigParser parser;
        auto [rules, exclusions] = parser.get_objects_from_json_file(jsonPath);
        for(const auto& rule : rules)
        {
            m_ioctl.add_rule(rule);
        }

        for(const auto& exclusion : exclusions)
        {
            m_ioctl.add_exclusion(exclusion);
        }
    }

    void Menu::addSingleRule() 
    {
        int option = GetRuleTypeViaCLI();
        std::cout << "Empty values will use difaults\n" << std::endl;

        switch (option) 
        {
            case 1: 
            {
                addSingleExecveRule();
                break;
            }
            case 2: 
            {
                addSingleOpenRule();
                break;
            }
            default: std::cout << "Invalid option. Please try again." << std::endl;
        }
    }

    int Menu::GetRuleTypeViaCLI()
    {
        int option;
        std::cout << "\nRule type:\n"
                  << "1 - execve rule\n"
                  << "2 - open/openat rule\n"
                  << "Enter your choice: ";
        std::cin >> option;
        std::cout << std::endl;
        return option;
    }

    void Menu::addSingleExecveRule() 
    {
        userspace_execve_rule new_rule;
        new_rule.build_rule_via_cli();
        struct rule rule = { };
        rule.type = execve_rule_type;
        rule.data.execve = new_rule.to_execve_rule();
        m_ioctl.add_rule(rule);
    }

    void Menu::addSingleOpenRule() 
    {
        userspace_open_rule new_rule;
        new_rule.build_rule_via_cli();
        struct rule rule = { };
        rule.type = open_rule_type;
        rule.data.open = new_rule.to_open_rule();
        m_ioctl.add_rule(rule);
    }

    void Menu::addSingleExclusion() 
    {
        std::cout << "binary_path to exclude:  ";
        std::string binary_path;
        std::cout << std::endl;
        std::getline(std::cin, binary_path);
        m_ioctl.add_exclusion(binary_path);
    }

    void Menu::deleteAllRules() 
    {
        m_ioctl.delete_all_rules();
    }

    void Menu::deleteAllExclusions() 
    {
        m_ioctl.delete_all_exclusions();
    }

    void Menu::printAllRules() 
    {
        m_ioctl.print_rules();
    }

    void Menu::printAllExclusions() 
    {
        m_ioctl.print_exclusions();
    }

    void Menu::clearCLI() 
    {
        system("clear");
    }
