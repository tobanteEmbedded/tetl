/*
Copyright (c) 2019-2021, Tobias Hienzsch
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

#include <stdio.h>  // for printf

#include "etl/cassert.hpp"  // for assert
#include "etl/utility.hpp"  // for pair

auto main() -> int
{
    // SWAP
    auto v1 = 42;
    auto v2 = 100;
    etl::swap(v1, v2);
    assert(v1 == 100);
    assert(v2 == 42);

    // EXCHANGE
    auto val = 1;
    assert(etl::exchange(val, 2) == 1);

    // AS CONST
    auto c = 1;
    assert(!etl::is_const_v<decltype(c)>);
    assert(etl::is_const_v<etl::remove_reference_t<decltype(etl::as_const(c))>>);

    // CMP
    assert(etl::cmp_equal(42, 42));
    assert(!etl::cmp_equal(42UL, 100UL));
    assert(etl::cmp_not_equal(42UL, 100UL));

    // IN_RANGE
    using etl::int32_t;
    using etl::int64_t;
    assert(etl::in_range<int64_t>(0));
    assert(etl::in_range<int64_t>(etl::numeric_limits<int64_t>::min()));
    assert(etl::in_range<int64_t>(etl::numeric_limits<int64_t>::max()));
    assert(!etl::in_range<int32_t>(etl::numeric_limits<int64_t>::min()));
    assert(!etl::in_range<int32_t>(etl::numeric_limits<int64_t>::max()));

    // PAIR construct
    auto p1 = etl::pair<int, float> {1, 42.0f};
    assert(p1.first == 1);

    auto p2 = etl::make_pair(2, 1.43f);
    assert(p2.first == 2);

    auto p3 = p1;
    assert(p3.first == 1);

    // PAIR compare
    assert(p1 == p3);
    assert(p1 != p2);
    assert(p2 > p3);
    assert(p3 < p2);

    // PAIR swap
    etl::swap(p2, p3);
    assert(p2.first == 1);
    assert(p3.first == 2);

    return 0;
}
