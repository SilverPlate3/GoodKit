#include "Ioctl.hpp"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>

        Ioctl::Ioctl()
        {
            m_rules_fd = open(RULES_DEVICE_PATH, O_WRONLY);
            if (m_rules_fd < 0)
            {
                std::cout << "Failed to open " << RULES_DEVICE_PATH << std::endl;
            }

            m_exclusions_fd = open(EXCLUSIONS_DEVICE_PATH, O_WRONLY);
            if (m_exclusions_fd < 0)
            {
                std::cout << "Failed to open device file. errno: " << errno << std::endl;
            }
        }

        Ioctl::~Ioctl()
        {
            if (m_rules_fd > 0)
            {
                close(m_rules_fd);
            }

            if (m_exclusions_fd > 0)
            {
                close(m_exclusions_fd);
            }
        }

        void Ioctl::add_rule(const rule& rule)
        {
            if(ioctl(m_rules_fd, ADD_RULE, &rule) < 0)
            {
                std::cout << "Failed to add rule. errno: " << errno << std::endl;
            }
        }

        void Ioctl::add_exclusion(const std::string& exclusion)
        {
            if(ioctl(m_exclusions_fd, ADD_BINARY_EXCLUSION, exclusion.c_str()) < 0)
            {
                std::cout << "Failed to add exclusion. errno: " << errno << std::endl;
            }
        }

        void Ioctl::delete_all_rules()
        {
            if(ioctl(m_rules_fd, DELETE_RULES, NULL) < 0)
            {
                std::cout << "Failed to delete all rules. errno: " << errno << std::endl;
            }
        }

        void Ioctl::delete_all_exclusions()
        {
            if(ioctl(m_exclusions_fd, DELETE_EXCLUSIONS, NULL) < 0)
            {
                std::cout << "Failed to delete all exclusions. errno: " << errno << std::endl;
            }
        }

        void Ioctl::print_rules()
        {
            if(ioctl(m_rules_fd, PRINT_ALL_RULLES, NULL) < 0)
            {
                std::cout << "Failed to print rules. errno: " << errno << std::endl;
            }
        }

        void Ioctl::print_exclusions()
        {
            if(ioctl(m_exclusions_fd, PRINT_ALL_EXCLUSIONS, NULL) < 0)
            {
                std::cout << "Failed to print exclusions. errno: " << errno << std::endl;
            }
        }