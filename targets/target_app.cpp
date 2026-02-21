#include <iostream>
#include <vector>
#include <unistd.h>

using namespace std;

void healthy_function()
{
    void *ptr = malloc(512);
    free(ptr);
}

void potential_leak()
{
    void *ptr = malloc(1024);
    cout << "Allocated 1KB at" << ptr << endl;
}

int main()
{
    while (true)
    {
        potential_leak();
        sleep(2);
    }
    return 0;
}