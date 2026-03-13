// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Comprehensive C++ allocation test for trace-malloc
// Tests: new/delete, new[]/delete[], std containers, smart pointers
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <unistd.h>

#define N 10

int main() {
    printf("=== scalar new/delete ===\n");
    for (int i = 0; i < N; i++) {
        int *p = new int(42 + i);
        delete p;
    }

    printf("=== array new[]/delete[] ===\n");
    for (int i = 0; i < N; i++) {
        int *arr = new int[100 * (i + 1)];
        std::memset(arr, 0, sizeof(int) * 100 * (i + 1));
        delete[] arr;
    }

    printf("=== std::vector ===\n");
    {
        std::vector<int> v;
        for (int i = 0; i < 1000; i++)
            v.push_back(i);
        v.clear();
        v.shrink_to_fit();
    }

    printf("=== std::string ===\n");
    {
        std::string s;
        for (int i = 0; i < 100; i++)
            s += "hello world ";
        s.clear();
        s.shrink_to_fit();
    }

    printf("=== std::map ===\n");
    {
        std::map<int, std::string> m;
        for (int i = 0; i < 100; i++)
            m[i] = "value_" + std::to_string(i);
        m.clear();
    }

    printf("=== std::unique_ptr ===\n");
    for (int i = 0; i < N; i++) {
        auto p = std::make_unique<int[]>(256);
        p[0] = i;
    }

    printf("=== std::shared_ptr ===\n");
    for (int i = 0; i < N; i++) {
        auto p = std::make_shared<int>(i);
    }

    // Intentional leak
    printf("=== intentional leak ===\n");
    int *leaked = new int[1024];
    (void)leaked;

    printf("All C++ tests passed.\n");
    return 0;
}
