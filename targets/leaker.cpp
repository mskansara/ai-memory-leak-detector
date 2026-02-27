#include <iostream>
#include <vector>
#include <unistd.h>
#include <cstring>

void deliberate_leak()
{
    // We allocate 1MB and "forget" to delete it
    char *buffer = (char *)malloc(1024 * 1024);
    std::memset(buffer, 1, 1024 * 1024);
    std::cout << "[Target] Leaked 1MB at address: " << (void *)buffer << std::endl;
}

int main()
{
    std::cout << "Starting Leaky App. My PID is: " << getpid() << std::endl;
    std::cout << "I will leak 1MB every 2 seconds. Press Ctrl+C to stop." << std::endl;

    while (true)
    {
        deliberate_leak();
        sleep(2);
    }
    return 0;
}