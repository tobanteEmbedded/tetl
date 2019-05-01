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

#include <assert.h>  // assert
#include <stdio.h>   // printf

// TAETL
#include "taetl/array.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::Array<int, 16> t_array;

    // Empty
    assert(t_array.empty());

    // Add 2 elements to the back
    t_array.push_back(1);
    t_array.push_back(2);

    // Test const iterators
    for (const auto& item : t_array)
    {
        assert(item != 0);
    }

    assert(t_array.empty() == false);
    assert(t_array[0] == 1);
    assert(t_array[1] == 2);
    assert(t_array.capacity() == 16);
    assert(t_array.size() == 2);

    // Test non-const iterators
    for (auto& item : t_array)
    {
        item += 1;
    }

    assert(t_array.empty() == false);
    assert(t_array[0] == 2);
    assert(t_array[1] == 3);
    assert(t_array.capacity() == 16);
    assert(t_array.size() == 2);

    // POP BACK
    t_array.pop_back();

    assert(t_array.empty() == false);
    assert(t_array[0] == 2);
    assert(t_array.capacity() == 16);
    assert(t_array.size() == 1);

    // CLEAR
    t_array.clear();

    assert(t_array.empty() == true);
    assert(t_array.capacity() == 16);
    assert(t_array.size() == 0);

    return 0;
}