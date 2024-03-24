#include "../IoctlContracts.h"
#include "../Alert.h"

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

    if(ioctl(fd, PRINT_ALL_RULLES, NULL) < 0)
    {
        std::cout << "PRINT_ALL_RULLES failed. errno: " << errno << std::endl;
    }

    if(ioctl(fd, ADD_RULE, &rule4) < 0)
    {
        std::cout << "rule4 failed. errno: " << errno << std::endl;
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
            std::cout << "Received alert:  \nevent.execve.full_command:" << alert->event.execve.full_command << "\nrule.full_command: "<< alert->rule.data.execve.full_command << std::endl;
        }

        memset(nlh, 0, NLMSG_SPACE(sizeof(struct alert)));
    }
    
    free(nlh);
    close(sock_fd);
}
