#include "../IoctlContracts.h"

#include <sys/ioctl.h>
#include <iostream>
#include <fcntl.h>
#include <string.h>
#include <thread>
#include <chrono>
#include <memory>

int main()
{
    struct rule* rule1 = new struct rule;
    rule1->type = execve;
    rule1->data.execve.uid = 1111;
    strncpy(rule1->data.execve.full_command, "Rule 1 -n /path/to/executable", sizeof(rule1->data.execve.full_command));

    struct rule* rule2 = new struct rule;
    rule2->type = execve;
    rule2->data.execve.uid = 2;
    strncpy(rule2->data.execve.full_command, "Rule 2 -n ", sizeof(rule2->data.execve.full_command));

    struct rule* rule3 = new struct rule;
    rule3->type = execve;
    rule3->data.execve.uid = 33333;
    strncpy(rule3->data.execve.full_command, "Rule 3 -n AAAAAAAAAAAAAAAA", sizeof(rule3->data.execve.full_command));

    struct rule* rule4 = new struct rule;
    rule4->type = execve;
    rule4->data.execve.uid = 44;
    strncpy(rule4->data.execve.full_command, "Rule 4 !@#$%^&*()", sizeof(rule4->data.execve.full_command));
    
    struct rule* rule5 = new struct rule;
    rule5->type = execve;
    rule5->data.execve.gid = 1111;
    strncpy(rule5->data.execve.full_command, "Rule 5 -n /path/to/executable", sizeof(rule5->data.execve.full_command));

    struct rule* rule6 = new struct rule;
    rule6->type = execve;
    rule6->data.execve.uid = 6;
    strncpy(rule6->data.execve.full_command, "Rule 6 ", sizeof(rule6->data.execve.full_command));

    int fd = open(RULES_DEVICE_PATH, O_WRONLY);
    if(fd < 0)
    {
        std::cout << "Failed to open device file. errno: " << errno << std::endl;
        return -1;
    }

    if(ioctl(fd, ADD_RULE, rule1) < 0)
    {
        std::cout << "rule1 failed. errno: " << errno << std::endl;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));

    if(ioctl(fd, ADD_RULE, rule2) < 0)
    {
        std::cout << "rule2 failed. errno: " << errno << std::endl;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));

    if(ioctl(fd, ADD_RULE, rule3) < 0)
    {
        std::cout << "rule3 failed. errno: " << errno << std::endl;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));

    if(ioctl(fd, ADD_RULE, rule4) < 0)
    {
        std::cout << "rule4 failed. errno: " << errno << std::endl;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    if(ioctl(fd, ADD_RULE, rule5) < 0)
    {
        std::cout << "rule5 failed. errno: " << errno << std::endl;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));

    if(ioctl(fd, ADD_RULE, rule6) < 0)
    {
        std::cout << "rule6 failed. errno: " << errno << std::endl;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));

    if(ioctl(fd, PRINT_ALL_RULLES, NULL) < 0)
    {
        std::cout << "PRINT_ALL_RULLES failed. errno: " << errno << std::endl;
    }

    delete rule1;
    delete rule2;
    delete rule3;
    delete rule4;
    delete rule5;
    delete rule6;

    return 0;
}