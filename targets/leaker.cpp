#include <iostream>
#include <unistd.h>

int main()
{
    std::cout << "🚀 Leaker started. PID: " << getpid() << std::endl;

    // Leak 1MB every second for 5 minutes
    for (int i = 0; i < 300; i++)
    {
        int *leak = new int[250000]; // ~1MB
        leak[0] = i;                 // Ensure memory is actually touched
        std::cout << "Iteration " << i << ": Leaked 1MB..." << std::endl;
        sleep(1);
    }
    return 0;
}