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
#include <stdio.h>

#include "etl/algorithm.hpp"
#include "etl/map.hpp"
#include "etl/vector.hpp"
#include "etl/warning.hpp"

auto basic_usage() -> void
{
    // Create map with no elements and a capacity of 16 key-value pairs.
    auto map = etl::map<int, float, 16> {};
    printf("size: %lu", map.size());
}

auto custom_compare() -> void
{
    // Typedef for the value being stored inside the map.
    using value_t = etl::stack_vector<float, 4>;

    // Lambda for comparing to objects of type value_t.
    auto compare = [](value_t& lhs, value_t& rhs) { return lhs.size() < rhs.size(); };

    // Create map of type value_t with the comparator compare, no elements and a capacity
    // of 16 key-value pairs.
    auto data = etl::map<int, value_t, 16, decltype(compare)> {};
    etl::ignore_unused(data);
}

auto main() -> int
{
    basic_usage();
    custom_compare();
    return 0;
}