#include <assert.h>  // assert
#include <stdio.h>   // printf

// TAETL
#include "taetl/algorithm.hpp"
#include "taetl/array.hpp"

int main()
{
    // -------------------------- FOR_EACH --------------------------
    // Create array with capacity of 16 and size of 0
    taetl::Array<double, 16> t_array;

    // Add elements to the back
    t_array.push_back(1.0);
    t_array.push_back(2.0);
    t_array.push_back(3.0);
    t_array.push_back(4.0);

    // Check how often for_each calls the unary function
    int counter{};
    auto increment_counter = [&counter](auto&) { counter += 1; };

    // for_each
    taetl::for_each(t_array.begin(), t_array.end(), increment_counter);
    assert(counter == 4);

    // for_each_n
    counter = 0;
    taetl::for_each_n(t_array.begin(), 2, increment_counter);
    assert(counter == 2);

    // -------------------------- FIND --------------------------
    taetl::Array<int, 16> t_array_2;
    // Add elements to the back
    t_array_2.push_back(1);
    t_array_2.push_back(2);
    t_array_2.push_back(3);
    t_array_2.push_back(4);

    auto result1 = taetl::find(t_array_2.begin(), t_array_2.end(), 3);
    assert(result1 != t_array_2.end());

    auto result2 = taetl::find(t_array_2.begin(), t_array_2.end(), 5);
    assert(result2 == t_array_2.end());

    return 0;
}