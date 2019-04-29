#include <assert.h> /* assert */
#include <stdio.h>  /* printf */

// TAETL
#include "taetl/algorithm.hpp"
#include "taetl/string.hpp"

/** Handy function for avoiding unused variables warning. */
template <typename... Types>
constexpr void ignoreUnused(Types&&...) noexcept
{
}

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::String<char, 16> t_string{};

    // INIT
    assert(t_string.empty() == true);
    assert(t_string.capacity() == 16);
    assert(t_string.size() == 0);
    assert(t_string.length() == 0);

    for (const auto& c : t_string)
    {
        ignoreUnused(c);
        assert(c == 0);
    }

    // APPEND 4 CHARACTERS
    const char* cptr = "C-string";
    t_string.append(cptr, 4);

    assert(t_string.empty() == false);
    assert(t_string.capacity() == 16);
    assert(t_string.size() == 4);
    assert(t_string.length() == 4);
    assert(t_string[0] == 'C');
    assert(t_string[1] == '-');
    assert(t_string[2] == 's');
    assert(t_string[3] == 't');
    assert(t_string[4] == 0);
    assert(t_string.at(4) == 0);

    // APPEND 5X SAME CHARACTER
    t_string.append(5, 'a');

    assert(t_string.empty() == false);
    assert(t_string.capacity() == 16);
    assert(t_string.size() == 9);
    assert(t_string.length() == 9);
    assert(t_string[0] == 'C');
    assert(t_string[1] == '-');
    assert(t_string[2] == 's');
    assert(t_string[3] == 't');
    assert(t_string[4] == 'a');
    assert(t_string[5] == 'a');
    assert(t_string[6] == 'a');
    assert(t_string[7] == 'a');
    assert(t_string[8] == 'a');
    assert(t_string[9] == 0);
    assert(t_string.at(9) == 0);

    // APPLY ALGORITHM
    taetl::for_each(t_string.begin(), t_string.end(), [](auto& c) { c += 1; });
    assert(t_string[4] == 'b');
    assert(t_string[5] == 'b');
    assert(t_string[6] == 'b');
    assert(t_string[7] == 'b');
    assert(t_string[8] == 'b');

    // CLEAR
    t_string.clear();
    assert(t_string.capacity() == 16);
    assert(t_string.empty());
    assert(t_string.size() == 0);

    for (const auto& c : t_string)
    {
        ignoreUnused(c);
        assert(c == 0);
    }

    return 0;
}