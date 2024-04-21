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
                  << "1 - Add rules and exclusions via json\n"
                  << "2 - Delete all rules\n"
                  << "3 - Delete all exclusions\n"
                  << "4 - Print all rules (dmesg)\n"
                  << "5 - Print all exclusions (dmesg)\n"
                  << "6 - Clear CLI\n"
                  << "Enter your choice: ";
    }

    void Menu::processOption(int option) 
    {
        std::cout << std::endl;
        switch (option) 
        {
            case 1: addMultipleRulesAndExclusions(); break;
            case 2: deleteAllRules(); break;
            case 3: deleteAllExclusions(); break;
            case 4: printAllRules(); break;
            case 5: printAllExclusions(); break;
            case 6: clearCLI(); break;
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
