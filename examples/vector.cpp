// SPDX-License-Identifier: BSL-1.0

#undef NDEBUG

#include <etl/cassert.hpp>
#include <etl/vector.hpp>

struct Person {
    constexpr Person(int a, int e) noexcept : age{a}, experience{e} { }

    friend constexpr auto operator==(Person lhs, Person rhs) noexcept -> bool = default;

    int age{};
    int experience{};
};

auto main() -> int
{
    // Unlike a std::vector you will have to decide which maximum capacity you
    // need. Apart from that it behaves almost the same as the standard version.
    etl::static_vector<Person, 32> people{};
    assert(people.empty());
    assert(people.capacity() == 32);

    // You can push_back/emplace_back into the vector
    people.push_back(Person{20, 0});
    assert(people.size() == 1);
    assert(people.back().age == 20);

    people.emplace_back(90, 100);
    assert(people.size() == 2);
    assert(people.back().age == 90);

    // You can make copies.
    auto const copy = people;

    // You can compare vectors
    assert(copy == people);

    // You can apply algorithms.
    auto levelUp = [](auto p) {
        p.experience += 1;
        return p;
    };

    etl::transform(begin(people), end(people), begin(people), levelUp);
    assert(people[0].experience == 1);
    assert(people[1].experience == 101);
    assert(copy != people);

    return 0;
}
