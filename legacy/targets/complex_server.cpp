#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <unistd.h>

// --- SCENARIO 1: The "Flatline" ---
// Simulates loading a config file at startup.
// It allocates memory once and never frees it.
// Our ML should IGNORE this because there is no continuous growth.
std::vector<void *> global_config;
void initialize_system()
{
    std::cout << "[SYSTEM] Loading configuration (Flatline allocation)..." << std::endl;
    for (int i = 0; i < 50; ++i)
    {
        global_config.push_back(malloc(1024 * 10)); // 10KB chunks
    }
}

// --- SCENARIO 2: The "Healthy Traffic" ---
// Simulates processing a user request.
// It allocates a buffer, does some work, and FREES it.
// Our ML should IGNORE this because net memory usage remains stable.
void process_healthy_request()
{
    void *temp_buffer = malloc(2048); // 2KB chunk
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    free(temp_buffer);
}

// --- SCENARIO 3: The "Actual Leak" ---
// Simulates a bug where user sessions are cached but never evicted.
// Our ML MUST FLAG this path because it grows continuously over time.
std::vector<void *> forgotten_sessions;
void cache_user_session_leak()
{
    // We intentionally leak 512 bytes every time this is called
    forgotten_sessions.push_back(malloc(512));
}

int main()
{
    std::cout << "Starting Complex Server Simulation. PID: " << getpid() << std::endl;

    initialize_system();

    int cycle_count = 0;
    while (true)
    {
        process_healthy_request();

        // Only leak every 5th cycle to make it a "slow" leak
        if (cycle_count % 5 == 0)
        {
            cache_user_session_leak();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        cycle_count++;
    }

    return 0;
}