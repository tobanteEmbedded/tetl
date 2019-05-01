/*
Copyright (c) 2019, Tobias Hienzsch
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

// MICROCATCH
#include "micro_catch/micro_catch.hpp"

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
    microcatch::EQUAL(counter, 4);

    // for_each_n
    counter = 0;
    taetl::for_each_n(t_array.begin(), 2, increment_counter);
    microcatch::EQUAL(counter, 2);

    // -------------------------- FIND --------------------------
    taetl::Array<int, 16> t_array_2;
    // Add elements to the back
    t_array_2.push_back(1);
    t_array_2.push_back(2);
    t_array_2.push_back(3);
    t_array_2.push_back(4);

    // find
    auto result1 = taetl::find(t_array_2.begin(), t_array_2.end(), 3);
    microcatch::NOT_EQUAL(result1, t_array_2.end());

    auto result2 = taetl::find(t_array_2.begin(), t_array_2.end(), 5);
    microcatch::EQUAL(result2, t_array_2.end());

    // find_if
    auto result3
        = taetl::find_if(t_array_2.begin(), t_array_2.end(),
                         [](auto& x) -> bool { return x % 2 ? true : false; });
    microcatch::NOT_EQUAL(result3, t_array_2.end());

    auto result4 = taetl::find_if(
        t_array_2.begin(), t_array_2.end(),
        [](auto& x) -> bool { return x == 100 ? true : false; });
    microcatch::EQUAL(result4, t_array_2.end());

    // find_if_not
    auto result5 = taetl::find_if_not(
        t_array_2.begin(), t_array_2.end(),
        [](auto& x) -> bool { return x % 2 ? true : false; });
    microcatch::NOT_EQUAL(result5, t_array_2.end());

    auto result6 = taetl::find_if_not(
        t_array_2.begin(), t_array_2.end(),
        [](auto& x) -> bool { return x == 100 ? true : false; });
    microcatch::NOT_EQUAL(result6, t_array_2.end());

    return 0;
}