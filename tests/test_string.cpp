#include <assert.h> /* assert */
#include <stdio.h>  /* printf */

// TAETL
#include "taetl/string.h"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::String<char, 16> t_string{};

    // INIT
    assert(t_string.capacity() == 16);
    assert(t_string.size() == 0);
    assert(t_string.length() == 0);

    for (const auto& c : t_string)
    {
        assert(c == 0);
    }

    // APPEND 4 CHARACTERS
    const char* cptr = "C-string";
    t_string.append(cptr, 4);

    assert(t_string.capacity() == 16);
    assert(t_string.size() == 4);
    assert(t_string.length() == 4);
    assert(t_string[0] == 'C');

    return 0;
}