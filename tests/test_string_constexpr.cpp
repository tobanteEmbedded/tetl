// TAETL
#include "taetl/string.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    constexpr taetl::String<char, 16> t_string{};

    static_assert(t_string.empty() == true, "String empty");
    static_assert(t_string.capacity() == 16, "String capacity");
    static_assert(t_string.size() == 0, "String size");
    static_assert(t_string.length() == 0, "String length");

    // Create array with capacity of 16 and size of 0
    constexpr auto t_string_2 = []() {
        taetl::String<char, 16> str{};
        // APPEND 4 CHARACTERS
        const char* cptr = "C-string";
        str.append(cptr, 4);
        return str;
    }();

    static_assert(t_string_2.empty() == false, "String empty");
    static_assert(t_string_2.capacity() == 16, "String capacity");
    static_assert(t_string_2.size() == 4, "String size");
    static_assert(t_string_2.length() == 4, "String length");
    static_assert(t_string_2[0] == 'C', "String element");
    static_assert(t_string_2[1] == '-', "String element");
    static_assert(t_string_2[2] == 's', "String element");
    static_assert(t_string_2[3] == 't', "String element");
    static_assert(t_string_2[4] == 0, "String element");
    static_assert(t_string_2.at(4) == 0, "String element");

    return 0;
}