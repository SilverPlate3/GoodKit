#pragma once

#include "../Kernel/Alert.h"
#include "../Kernel/Netlink/NetlinkSettings.h"

#include <sys/socket.h>
#include <string>

class Alerts
{
public:

    void listen_to_alerts();

private:

    int bind_netlink_socket();

    void print_alert(const struct alert& alert);

    std::string execve_alert_to_string(const struct alert& alert);

    std::string open_alert_to_string(const struct alert& alert);
};