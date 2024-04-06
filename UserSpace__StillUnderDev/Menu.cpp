#include "ConfigParser/ConfigParser.hpp"
#include "Menu.hpp"
#include "Ioctl.hpp"

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
        // TODO: implement this
        std::cout << "Adding a single rule..." << std::endl;
    }

    void Menu::addSingleExclusion() 
    {
        // TODO: implement this
        std::cout << "Adding a single exclusion...\n";
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
