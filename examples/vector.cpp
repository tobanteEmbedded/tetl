// SPDX-License-Identifier: BSL-1.0

// #undef NDEBUG

#include "etl/vector.hpp" // for static_vector

#include "etl/cassert.hpp" // for assert
#include "etl/cctype.hpp"  // for toupper

#include <stdio.h>  // for printf
#include <stdlib.h> // for EXIT_SUCCESS

struct Person {
    constexpr Person(int a, int e) noexcept : age { a }, experience { e } { }
    int age {};
    int experience {};
};

constexpr auto operator==(Person lhs, Person rhs) noexcept -> bool
{
    return lhs.age == rhs.age && lhs.experience == rhs.experience;
}

auto main() -> int
{
    // Unlike a std::vector you will have to decide which maximum capacity you
    // need. Apart from that it behaves almost the same as the standard version.
    etl::static_vector<Person, 32> people {};
    TETL_ASSERT(people.empty());
    TETL_ASSERT(people.capacity() == 32);

    // You can push_back/emplace_back into the vector
    people.push_back(Person { 20, 0 });
    TETL_ASSERT(people.size() == 1);
    TETL_ASSERT(people.back().age == 20);

    people.emplace_back(90, 100);
    TETL_ASSERT(people.size() == 2);
    TETL_ASSERT(people.back().age == 90);

    // You can make copies.
    auto const copy = people;

    // You can compare vectors
    TETL_ASSERT(copy == people);

    // You can apply algorithms.
    auto levelUp = [](auto p) {
        p.experience += 1;
        return p;
    };

    etl::transform(begin(people), end(people), begin(people), levelUp);
    TETL_ASSERT(people[0].experience == 1);
    TETL_ASSERT(people[1].experience == 101);
    TETL_ASSERT(copy != people);

    return EXIT_SUCCESS;
}
