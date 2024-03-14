// SPDX-License-Identifier: BSL-1.0

#undef NDEBUG

#include <etl/bitset.hpp>  // for bitset, bitset<>::reference
#include <etl/cassert.hpp> // for TETL_ASSERT

#include <stdlib.h> // for EXIT_SUCCESS

auto main() -> int
{
    auto bits = etl::bitset<8>();
    TETL_ASSERT(bits.none() == true);
    TETL_ASSERT(bits.any() == false);
    TETL_ASSERT(bits.all() == false);
    TETL_ASSERT(bits.test(0) == false);

    bits.set(0);
    TETL_ASSERT(bits.test(0) == true);
    TETL_ASSERT(bits.count() == 1);

    bits.set(1);
    TETL_ASSERT(bits.test(1) == true);
    TETL_ASSERT(bits.count() == 2);

    bits.reset(1);
    TETL_ASSERT(bits.test(1) == false);

    bits.reset();
    TETL_ASSERT(bits.test(0) == false);

    etl::bitset<8>::reference ref = bits[0];
    TETL_ASSERT(ref == false);
    TETL_ASSERT(~ref == true);

    ref = true;
    TETL_ASSERT(ref == true);
    TETL_ASSERT(~ref == false);

    ref.flip();
    TETL_ASSERT(ref == false);
    TETL_ASSERT(~ref == true);

    return EXIT_SUCCESS;
}
