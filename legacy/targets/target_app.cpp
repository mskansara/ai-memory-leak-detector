#include <iostream>
#include <vector>
#include <unistd.h>
#include <stdlib.h>

using namespace std;

// BEHAVIOR A: The "Steady Leak" (Classic Villain)
// The count will increase linearly forever.
void steady_leak()
{
    void *ptr = malloc(1024);
    // No free()
}

// BEHAVIOR B: The "Healthy Cycle" (Good Citizen)
// In your entry-only sniffer, this STILL shows allocations,
// but the AI will learn the rate is usually lower or tied to specific events.
void healthy_worker()
{
    void *ptr = malloc(512);
    free(ptr);
}

// BEHAVIOR C: The "Burst" (The False Positive)
// Allocates a lot at once, then stops. This tests if your AI
// gets tricked by sudden activity that isn't a long-term leak.
void startup_burst()
{
    for (int i = 0; i < 50; i++)
    {
        void *ptr = malloc(64);
        free(ptr);
    }
}

// BEHAVIOR D: The "Slow Creep" (The Hardest to Catch)
// Only leaks once every 10 seconds.
void slow_creep()
{
    void *ptr = malloc(2048);
}

int main()
{
    int counter = 0;
    cout << "Target App Running. PID: " << getpid() << std::endl;

    while (true)
    {
        healthy_worker(); // Every 1 second

        if (counter < 1)
        {
            startup_burst(); // Only happens at the very start
        }

        steady_leak(); // Every 1 second

        if (counter % 10 == 0)
        {
            slow_creep(); // Every 10 seconds
        }

        sleep(1);
        counter++;
    }
    return 0;
}