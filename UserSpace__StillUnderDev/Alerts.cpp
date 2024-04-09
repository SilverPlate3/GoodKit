#include "Alerts.hpp"

#include <linux/netlink.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

    void Alerts::listen_to_alerts()
    {
        struct sockaddr_nl dest_addr;
        struct iovec iov;
        struct msghdr msg;

        int sock_fd = bind_netlink_socket();
        if(sock_fd < 0)
        {
            return;
        }

        memset(&dest_addr, 0, sizeof(dest_addr));
        memset(&iov, 0, sizeof(iov));
        memset(&msg, 0, sizeof(msg));

        struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct alert)));
        if(nlh == NULL)
        {
            std::cout << "Failed to allocate memory for nlh" << std::endl;
            return;
        }
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
                print_alert(*alert);        
            }

            memset(nlh, 0, NLMSG_SPACE(sizeof(struct alert)));
        }

        free(nlh);
        close(sock_fd);
    }

    int Alerts::bind_netlink_socket()
    {
        struct sockaddr_nl src_addr;
        int sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_GOOD_KIT);
        if (sock_fd < 0)
        {
            std::cout << "Failed to create socket. errno: " << errno << std::endl;
            return sock_fd;
        }

        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = NETLINK_PORT_ID;

        bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
        return sock_fd;
    }

    void Alerts::print_alert(const struct alert& alert)
    {
        std::string to_print("--------- RECEIVED ALERT ---------\n");
        to_print += alert.rule.type == execve_rule_type ? execve_alert_to_string(alert) : open_alert_to_string(alert);
        std::cout << to_print << std::endl;
    }

    std::string Alerts::execve_alert_to_string(const struct alert& alert)
    {
        std::string alert_str;
        alert_str += std::string("Matched on execve rule:\n");
        alert_str += alert.rule.data.execve.binary_path == DEFAULT_BINARY_PATH ? "" : std::string("binary_path: ") + alert.rule.data.execve.binary_path + '\n';
        alert_str += alert.rule.data.execve.full_command == DEFAULT_FULL_COMMAND ? "" : std::string("full_command: ") + alert.rule.data.execve.full_command + '\n';
        alert_str += alert.rule.data.execve.uid == DEFAULT_UID ? "" : std::string("uid: ") + std::to_string(alert.rule.data.execve.uid) + '\n';
        alert_str += alert.rule.data.execve.gid == DEFAULT_GID ? "" : std::string("gid: ") + std::to_string(alert.rule.data.execve.gid) + '\n';
        alert_str += alert.rule.data.execve.argc == DEFAULT_ARGC ? "" : std::string("argc: ") + std::to_string(alert.rule.data.execve.argc) + '\n';
        alert_str += "prevention: " + std::to_string(alert.rule.data.execve.prevention) + '\n';

        alert_str += std::string("Malicious event:\n");
        alert_str += std::string("binary_path: ") + alert.event.execve.binary_path + '\n';
        alert_str += std::string("full_command: ") + alert.event.execve.full_command + '\n';
        alert_str += std::string("uid: ") + std::to_string(alert.event.execve.uid) + '\n';
        alert_str += std::string("gid: ") + std::to_string(alert.event.execve.gid) + '\n';
        alert_str += std::string("argc: ") + std::to_string(alert.event.execve.argc) + '\n';

        return alert_str;
    }

    std::string Alerts::open_alert_to_string(const struct alert& alert)
    {
        std::string alert_str;
        alert_str += std::string("Matched on open rule:\n");
        alert_str += alert.rule.data.open.binary_path == DEFAULT_BINARY_PATH ? "" : std::string("binary_path: ") + alert.rule.data.open.binary_path + '\n';
        alert_str += alert.rule.data.open.full_command == DEFAULT_FULL_COMMAND ? "" : std::string("full_command: ") + alert.rule.data.open.full_command + '\n';
        alert_str += alert.rule.data.open.target_path == DEFAULT_TARGET_PATH ? "" : std::string("target_path: ") + alert.rule.data.open.target_path + '\n';
        alert_str += alert.rule.data.open.uid == DEFAULT_UID ? "" : std::string("uid: ") + std::to_string(alert.rule.data.open.uid) + '\n';
        alert_str += alert.rule.data.open.gid == DEFAULT_GID ? "" : std::string("gid: ") + std::to_string(alert.rule.data.open.gid) + '\n';
        alert_str += alert.rule.data.open.flags == DEFAULT_FLAGS ? "" : std::string("flags: ") + std::to_string(alert.rule.data.open.flags) + '\n';
        alert_str += alert.rule.data.open.mode == DEFAULT_MODE ? "" : std::string("mode: ") + std::to_string(alert.rule.data.open.mode) + '\n';
        alert_str += "prevention: " + std::to_string(alert.rule.data.open.prevention) + '\n';

        alert_str += std::string("Malicious event:\n");
        alert_str += std::string("binary_path: ") + alert.event.open.binary_path + '\n';
        alert_str += std::string("full_command: ") + alert.event.open.full_command + '\n';
        alert_str += std::string("target_path: ") + alert.event.open.target_path + '\n';
        alert_str += std::string("uid: ") + std::to_string(alert.event.open.uid) + '\n';
        alert_str += std::string("gid: ") + std::to_string(alert.event.open.gid) + '\n';
        alert_str += std::string("mode: ") + std::to_string(alert.event.open.flags) + '\n';
        alert_str += std::string("flags: ") + std::to_string(alert.event.open.mode) + '\n';

        return alert_str;
    }