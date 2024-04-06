#include "Alerts.hpp"
#include "Menu.hpp"

#include <thread>

int main()
{
    Alerts alerts;
    std::thread alerts_thread(&Alerts::listen_to_alerts, &alerts);

    Menu menu;
    while (true)
    {
        menu.start();
    }

    if(alerts_thread.joinable())
    {
        alerts_thread.join();
    }
}