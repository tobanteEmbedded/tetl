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
#include "etl/utility.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("utility: exchange", "[utility]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)

{
    auto original = TestType {42};
    auto const b  = etl::exchange(original, TestType {43});
    REQUIRE(original == TestType {43});
    REQUIRE(b == TestType {42});

    auto const c = etl::exchange(original, TestType {44});
    REQUIRE(original == TestType {44});
    REQUIRE(c == TestType {43});
}

TEMPLATE_TEST_CASE("utility: cmp_equal", "[utility]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t)

{
    REQUIRE(etl::cmp_equal(0, TestType {0}));
    REQUIRE_FALSE(etl::cmp_equal(-1, TestType {0}));

    REQUIRE(etl::cmp_equal(TestType {0}, TestType {0}));
    REQUIRE(etl::cmp_equal(TestType {1}, TestType {1}));
    REQUIRE(etl::cmp_equal(TestType {42}, TestType {42}));

    REQUIRE_FALSE(etl::cmp_equal(TestType {0}, TestType {1}));
    REQUIRE_FALSE(etl::cmp_equal(TestType {1}, TestType {0}));
    REQUIRE_FALSE(etl::cmp_equal(TestType {42}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: cmp_not_equal", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t)

{
    REQUIRE(etl::cmp_not_equal(-1, TestType {0}));
    REQUIRE_FALSE(etl::cmp_not_equal(0, TestType {0}));

    REQUIRE_FALSE(etl::cmp_not_equal(TestType {0}, TestType {0}));
    REQUIRE_FALSE(etl::cmp_not_equal(TestType {1}, TestType {1}));
    REQUIRE_FALSE(etl::cmp_not_equal(TestType {42}, TestType {42}));

    REQUIRE(etl::cmp_not_equal(TestType {0}, TestType {1}));
    REQUIRE(etl::cmp_not_equal(TestType {1}, TestType {0}));
    REQUIRE(etl::cmp_not_equal(TestType {42}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: cmp_less", "[utility]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t)

{
    REQUIRE(etl::cmp_less(-1, TestType {0}));
    REQUIRE_FALSE(etl::cmp_less(0, TestType {0}));

    REQUIRE(etl::cmp_less(TestType {0}, TestType {1}));
    REQUIRE(etl::cmp_less(TestType {1}, TestType {2}));
    REQUIRE(etl::cmp_less(TestType {42}, TestType {43}));

    REQUIRE_FALSE(etl::cmp_less(TestType {2}, TestType {1}));
    REQUIRE_FALSE(etl::cmp_less(TestType {1}, TestType {0}));
    REQUIRE_FALSE(etl::cmp_less(TestType {44}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: cmp_greater", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t)

{
    REQUIRE_FALSE(etl::cmp_greater(-1, TestType {0}));
    REQUIRE_FALSE(etl::cmp_greater(0, TestType {0}));

    REQUIRE_FALSE(etl::cmp_greater(TestType {0}, TestType {1}));
    REQUIRE_FALSE(etl::cmp_greater(TestType {1}, TestType {2}));
    REQUIRE_FALSE(etl::cmp_greater(TestType {42}, TestType {43}));

    REQUIRE(etl::cmp_greater(TestType {2}, TestType {1}));
    REQUIRE(etl::cmp_greater(TestType {1}, TestType {0}));
    REQUIRE(etl::cmp_greater(TestType {44}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: cmp_less_equal", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t)

{
    REQUIRE(etl::cmp_less_equal(-1, TestType {0}));
    REQUIRE(etl::cmp_less_equal(0, TestType {0}));

    REQUIRE(etl::cmp_less_equal(TestType {0}, TestType {1}));
    REQUIRE(etl::cmp_less_equal(TestType {1}, TestType {1}));
    REQUIRE(etl::cmp_less_equal(TestType {1}, TestType {2}));
    REQUIRE(etl::cmp_less_equal(TestType {42}, TestType {43}));

    REQUIRE_FALSE(etl::cmp_less_equal(TestType {2}, TestType {1}));
    REQUIRE_FALSE(etl::cmp_less_equal(TestType {1}, TestType {0}));
    REQUIRE_FALSE(etl::cmp_less_equal(TestType {44}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: cmp_greater_equal", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t)

{
    REQUIRE_FALSE(etl::cmp_greater_equal(-1, TestType {0}));
    REQUIRE(etl::cmp_greater_equal(0, TestType {0}));
    REQUIRE(etl::cmp_greater_equal(TestType {0}, 0));

    REQUIRE_FALSE(etl::cmp_greater_equal(TestType {0}, TestType {1}));
    REQUIRE_FALSE(etl::cmp_greater_equal(TestType {1}, TestType {2}));
    REQUIRE_FALSE(etl::cmp_greater_equal(TestType {42}, TestType {43}));

    REQUIRE(etl::cmp_greater_equal(TestType {2}, TestType {2}));
    REQUIRE(etl::cmp_greater_equal(TestType {2}, TestType {1}));
    REQUIRE(etl::cmp_greater_equal(TestType {1}, TestType {0}));
    REQUIRE(etl::cmp_greater_equal(TestType {44}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: in_range", "[utility]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t)

{
    REQUIRE(etl::in_range<TestType>(0));
    REQUIRE(etl::in_range<TestType>(etl::numeric_limits<TestType>::min()));
    REQUIRE(etl::in_range<TestType>(etl::numeric_limits<TestType>::max()));
}

TEMPLATE_TEST_CASE("utility: in_range unsigned", "[utility]", etl::uint8_t,
                   etl::uint16_t, etl::uint32_t, etl::uint64_t)

{
    REQUIRE_FALSE(etl::in_range<TestType>(-1));
}