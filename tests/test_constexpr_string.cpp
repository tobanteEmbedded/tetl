// TAETL
#include "taetl/string.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    constexpr taetl::String<char, 16> t_string{};

    // INIT
    static_assert(t_string.empty() == true, "String empty");
    static_assert(t_string.capacity() == 16, "String capacity");
    static_assert(t_string.size() == 0, "String size");
    static_assert(t_string.length() == 0, "String length");

    return 0;
}