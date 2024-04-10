#include "../Kernel/IoctlContracts.h"
#include "../Kernel/Alert.h"
#include "../Kernel/Netlink/NetlinkSettings.h"

#include <sys/ioctl.h>
#include <iostream>
#include <fcntl.h>
#include <string.h>
#include <thread>
#include <chrono>
#include <memory>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>


void print_alerts();

int main()
{
    int fd = open(RULES_DEVICE_PATH, O_WRONLY);
    if(fd < 0)
    {
        std::cout << "Failed to open device file. errno: " << errno << std::endl;
        return -1;
    }

    int fd2 = open(EXCLUSIONS_DEVICE_PATH, O_WRONLY);
    if(fd2 < 0)
    {
        std::cout << "Failed to open device file. errno: " << errno << std::endl;
        return -1;
    }

    struct rule rule1 = {};
    rule1.type = execve_rule_type;
    strncpy(rule1.data.execve.binary_path, DEFAULT_BINARY_PATH, sizeof(rule1.data.execve.full_command));
    strncpy(rule1.data.execve.full_command, "ping 9.9.*", sizeof(rule1.data.execve.full_command));
    rule1.data.execve.uid = DEFAULT_UID;
    rule1.data.execve.gid = DEFAULT_GID;
    rule1.data.execve.argc = DEFAULT_ARGC;
    rule1.data.execve.prevention = 1;

    struct rule rule2 = {};
    rule2.type = execve_rule_type;
    strncpy(rule2.data.execve.binary_path, "/usr/bin/wget", sizeof(rule2.data.execve.full_command));
    strncpy(rule2.data.execve.full_command, "*Malicious.com", sizeof(rule2.data.execve.full_command));
    rule2.data.execve.uid = DEFAULT_UID;
    rule2.data.execve.gid = DEFAULT_GID;
    rule2.data.execve.argc = 3;
    rule2.data.execve.prevention = 1;

    struct rule rule3 = {};
    rule3.type = execve_rule_type;
    strncpy(rule3.data.execve.binary_path, DEFAULT_BINARY_PATH, sizeof(rule3.data.execve.full_command));
    strncpy(rule3.data.execve.full_command, "*/etc/passwd", sizeof(rule3.data.execve.full_command));
    rule3.data.execve.uid = 1000;
    rule3.data.execve.gid = 1000;
    rule3.data.execve.argc = DEFAULT_ARGC;
    rule3.data.execve.prevention = 1;

    struct rule rule4 = {};
    rule4.type = execve_rule_type;
    strncpy(rule4.data.execve.binary_path, "*netcat", sizeof(rule4.data.execve.full_command));
    strncpy(rule4.data.execve.full_command, DEFAULT_FULL_COMMAND, sizeof(rule4.data.execve.full_command));
    rule4.data.execve.uid = DEFAULT_UID;
    rule4.data.execve.gid = DEFAULT_GID;
    rule4.data.execve.argc = DEFAULT_ARGC;
    rule4.data.execve.prevention = 0;

    struct rule rule5 = {};
    rule5.type = open_rule_type;
    strncpy(rule5.data.open.binary_path, "/tmp/fileOpener.bin", sizeof(rule5.data.open.binary_path));
    strncpy(rule5.data.open.full_command, "/tmp/fileOpener.bin 1", sizeof(rule5.data.open.full_command));
    strncpy(rule5.data.open.target_path, "/tmp/1", sizeof(rule5.data.open.target_path));
    rule5.data.open.uid = 1000;
    rule5.data.open.gid = 1000;
    rule5.data.open.flags = O_RDWR;
    rule5.data.open.mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    rule5.data.open.prevention = 0;

    struct rule rule6 = {};
    rule6.type = open_rule_type;
    strncpy(rule6.data.open.binary_path, DEFAULT_BINARY_PATH, sizeof(rule6.data.open.binary_path));
    strncpy(rule6.data.open.full_command, DEFAULT_FULL_COMMAND, sizeof(rule6.data.open.full_command));
    strncpy(rule6.data.open.target_path, "/etc/hosts", sizeof(rule6.data.open.target_path));
    rule6.data.open.uid = DEFAULT_UID;
    rule6.data.open.gid = DEFAULT_GID;
    rule6.data.open.flags = O_WRONLY;
    rule6.data.open.mode = DEFAULT_MODE;
    rule6.data.open.prevention = 1;

    struct rule rule7 = {};
    rule7.type = open_rule_type;
    strncpy(rule7.data.open.binary_path, "/usr/bin/nano", sizeof(rule7.data.open.binary_path));
    strncpy(rule7.data.open.full_command, "*nano*", sizeof(rule7.data.open.full_command));
    strncpy(rule7.data.open.target_path, "/tmp/newFile.txt", sizeof(rule7.data.open.target_path));
    rule7.data.open.uid = DEFAULT_UID;
    rule7.data.open.gid = DEFAULT_GID;
    rule7.data.open.flags = O_CREAT;
    rule7.data.open.mode = S_IWUSR;
    rule7.data.open.prevention = 1;

    if(ioctl(fd, ADD_RULE, &rule1) < 0)
    {
        std::cout << "rule1 failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd, ADD_RULE, &rule2) < 0)
    {
        std::cout << "rule2 failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd, ADD_RULE, &rule3) < 0)
    {
        std::cout << "rule3 failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd, ADD_RULE, &rule4) < 0)
    {
        std::cout << "rule4 failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd, ADD_RULE, &rule5) < 0)
    {
        std::cout << "rule5 failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd, ADD_RULE, &rule6) < 0)
    {
        std::cout << "rule6 failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd, ADD_RULE, &rule7) < 0)
    {
        std::cout << "rule7 failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd, PRINT_ALL_RULLES, NULL) < 0)
    {
        std::cout << "PRINT_ALL_RULLES failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd2, ADD_BINARY_EXCLUSION, "*journald*") < 0)
    {
        std::cout << "ADD_BINARY_EXCLUSION failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd2, ADD_BINARY_EXCLUSION, "/usr/bin/sudo") < 0)
    {
        std::cout << "ADD_BINARY_EXCLUSION failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd2, ADD_BINARY_EXCLUSION, "*systemd-oomd") < 0)
    {
        std::cout << "ADD_BINARY_EXCLUSION failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd2, ADD_BINARY_EXCLUSION, "*node") < 0)
    {
        std::cout << "ADD_BINARY_EXCLUSION failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd2, PRINT_ALL_EXCLUSIONS, NULL) < 0)
    {
        std::cout << "PRINT_ALL_EXCLUSIONS failed. errno: " << errno << std::endl;
    }

    print_alerts();
}

void print_alerts()
{
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;

    int sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_GOOD_KIT);
    if (sock_fd < 0)
    {
        std::cout << "Failed to create socket. errno: " << errno << std::endl;
        return;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = NETLINK_PORT_ID; /* self pid */

    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&iov, 0, sizeof(iov));
    memset(&msg, 0, sizeof(msg));

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct alert)));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct alert));
    nlh->nlmsg_pid = NETLINK_PORT_ID;
    nlh->nlmsg_flags = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    int err_counter = 0;
    while (true)
    {
        int recv_bytes = recvmsg(sock_fd, &msg, 0);
        if(recv_bytes < 0)
        {
            std::cout << "Failed to receive alert. errno: " << errno << std::endl;
            ++err_counter;
            if(err_counter < 5)
            {
                continue;;
            }
            break;
        }
        else
        {
            struct alert *alert = (struct alert *)NLMSG_DATA(nlh);
            std::cout << "Received alert:  \nevent.execve.full_command:" << alert->event.execve.full_command << "\nrule.full_command: "<< alert->rule.data.execve.full_command << std::endl; // TODO: print the full event and rule
        }

        memset(nlh, 0, NLMSG_SPACE(sizeof(struct alert)));
    }
    
    free(nlh);
    close(sock_fd);
}
