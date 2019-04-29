/* assert example */
#include <assert.h> /* assert */
#include <stdio.h>  /* printf */

// TAETL
#include "taetl/array.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::Array<int, 16> t_array;

    // Add 2 elements to the back
    t_array.push_back(1);
    t_array.push_back(2);

    assert(t_array[0] == 1);
    assert(t_array[1] == 2);
    assert(t_array.capacity() == 16);
    assert(t_array.size() == 2);

    return 0;
}