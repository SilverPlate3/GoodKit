#pragma once

#include "../Alert.h"
#include "../Netlink/NetlinkSettings.h"

#include <sys/socket.h>
#include <string>

class Alerts
{
public:

    ~Alerts();

    void listen_to_alerts();

private:

    int subscribe_to_netlink();

    std::string execve_alert_to_string(const struct alert& alert);

    std::string open_alert_to_string(const struct alert& alert);

    void print_alert(const struct alert& alert);

    struct nlmsghdr *nlh = NULL;
    struct msghdr msg;
};