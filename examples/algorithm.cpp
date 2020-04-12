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

// C STANDARD
#include <stdio.h>

// TAETL
#include "taetl/algorithm.hpp"
#include "taetl/vector.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::make::vector<double, 16> t_array;

    // Add elements to the back
    t_array.push_back(1.0);
    t_array.push_back(2.0);
    t_array.push_back(3.0);
    t_array.push_back(4.0);

    // FOR_EACH
    auto print = [](auto& x) { printf("%f\n", x); };

    taetl::for_each(t_array.begin(), t_array.end(), print);
    taetl::for_each_n(t_array.begin(), 3,
                      [](const auto& x) { printf("%f\n", x * 2); });

    // FIND FIND_IF
    double n1 = 3.0;
    double n2 = 5;

    auto result1 = taetl::find(t_array.begin(), t_array.end(), n1);
    auto result2 = taetl::find(t_array.begin(), t_array.end(), n2);

    if (result1 != t_array.end()) { printf("v contains: %f\n", n1); }
    else
    {
        printf("v does not contain: %f\n", n1);
    }

    if (result2 != t_array.end()) { printf("v contains: %f\n", n2); }
    else
    {
        printf("v does not contain: %f\n", n2);
    }

    return 0;
}
