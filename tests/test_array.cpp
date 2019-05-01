#include <assert.h>  // assert
#include <stdio.h>   // printf

// TAETL
#include "taetl/array.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::Array<int, 16> t_array;

    // Empty
    assert(t_array.empty());

    // Add 2 elements to the back
    t_array.push_back(1);
    t_array.push_back(2);

    // Test const iterators
    for (const auto& item : t_array)
    {
        assert(item != 0);
    }

    assert(t_array.empty() == false);
    assert(t_array[0] == 1);
    assert(t_array[1] == 2);
    assert(t_array.capacity() == 16);
    assert(t_array.size() == 2);

    // Test non-const iterators
    for (auto& item : t_array)
    {
        item += 1;
    }

    assert(t_array.empty() == false);
    assert(t_array[0] == 2);
    assert(t_array[1] == 3);
    assert(t_array.capacity() == 16);
    assert(t_array.size() == 2);

    // POP BACK
    t_array.pop_back();

    assert(t_array.empty() == false);
    assert(t_array[0] == 2);
    assert(t_array.capacity() == 16);
    assert(t_array.size() == 1);

    return 0;
}