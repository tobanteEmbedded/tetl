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
#include "taetl/array.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::Array<int, 16> t_array;

    // Empty
    microcatch::EQUAL(t_array.empty(), true);

    // Add 2 elements to the back
    t_array.push_back(1);
    t_array.push_back(2);

    // Test const iterators
    for (const auto& item : t_array)
    {
        microcatch::NOT_EQUAL(item, 0);
    }

    microcatch::EQUAL(t_array.empty(), false);
    microcatch::EQUAL(t_array[0], 1);
    microcatch::EQUAL(t_array[1], 2);
    microcatch::EQUAL(t_array.front(), 1);
    microcatch::EQUAL(t_array.back(), 2);
    microcatch::EQUAL(t_array.capacity(), taetl::size_t(16));
    microcatch::EQUAL(t_array.size(), taetl::size_t(2));

    // Test non-const iterators
    for (auto& item : t_array)
    {
        item += 1;
    }

    microcatch::EQUAL(t_array.empty(), false);
    microcatch::EQUAL(t_array[0], 2);
    microcatch::EQUAL(t_array[1], 3);
    microcatch::EQUAL(t_array.capacity(), taetl::size_t(16));
    microcatch::EQUAL(t_array.size(), taetl::size_t(2));

    // POP BACK
    t_array.pop_back();

    microcatch::EQUAL(t_array.empty(), false);
    microcatch::EQUAL(t_array[0], 2);
    microcatch::EQUAL(t_array[100], 2);  // Out of bounds, return last item.
    microcatch::EQUAL(t_array.capacity(), taetl::size_t(16));
    microcatch::EQUAL(t_array.size(), taetl::size_t(1));

    // CLEAR
    t_array.clear();

    microcatch::EQUAL(t_array.empty(), true);
    microcatch::EQUAL(t_array.capacity(), taetl::size_t(16));
    microcatch::EQUAL(t_array.size(), taetl::size_t(0));

    // Add more elements then capacity
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1);
    t_array.push_back(1000);  // Should fail silently
    t_array.push_back(1000);  // Should fail silently

    for (const auto& item : t_array)
    {
        microcatch::EQUAL(item, 1);
    }

    return 0;
}