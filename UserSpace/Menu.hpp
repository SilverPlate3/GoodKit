#pragma once

#include "Ioctl.hpp"

class Menu 
{
public:
    void start();

private:
    void displayMenu();

    void processOption(int option);

    void addMultipleRulesAndExclusions();

    void addSingleRule();

    int GetRuleTypeViaCLI();

    void addSingleExecveRule();

    void addSingleOpenRule();

    void addSingleExclusion();

    void deleteAllRules();

    void deleteAllExclusions();

    void printAllRules();

    void printAllExclusions();

    void clearCLI();

    Ioctl m_ioctl;
};