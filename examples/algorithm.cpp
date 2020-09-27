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
#include "etl/static_vector.hpp"

auto main() -> int
{
    etl::static_vector<double, 16> vec;
    vec.push_back(1.0);
    vec.push_back(2.0);
    vec.push_back(3.0);
    vec.push_back(4.0);

    // FOR_EACH
    auto print = [](auto& x) { printf("%f\n", x); };

    etl::for_each(vec.begin(), vec.end(), print);
    etl::for_each_n(vec.begin(), 3, [](const auto& x) { printf("%f\n", x * 2); });

    // FIND FIND_IF
    double n1 = 3.0;
    double n2 = 5;

    auto* result1 = etl::find(vec.begin(), vec.end(), n1);
    auto* result2 = etl::find(vec.begin(), vec.end(), n2);

    if (result1 != vec.end()) { printf("v contains: %f\n", n1); }
    else
    {
        printf("v does not contain: %f\n", n1);
    }

    if (result2 != vec.end()) { printf("v contains: %f\n", n2); }
    else
    {
        printf("v does not contain: %f\n", n2);
    }

    return 0;
}
