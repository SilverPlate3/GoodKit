#pragma once

#include "../Kernel/IoctlContracts.h"

#include <string>

class Ioctl
{
public:
        Ioctl();

        ~Ioctl();

        void add_rule(const rule& rule);

        void add_exclusion(const std::string& exclusion);

        void delete_all_rules();

        void delete_all_exclusions();

        void print_rules();

        void print_exclusions();
    
private:

    int m_rules_fd = 0;
    int m_exclusions_fd = 0;
};