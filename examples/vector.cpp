/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#undef NDEBUG

#include "etl/vector.hpp"  // for static_vector

#include "etl/cctype.hpp"  // for toupper

#include <assert.h>  // for assert
#include <stdio.h>   // for printf
#include <stdlib.h>  // for EXIT_SUCCESS

struct Person
{
  constexpr Person(int a, int e) noexcept : age {a}, experience {e} { }
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
  assert(people.empty());
  static_assert(people.capacity() == 32);

  // You can push_back/emplace_back into the vector
  people.push_back(Person {20, 0});
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

  return EXIT_SUCCESS;
}
