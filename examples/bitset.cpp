// SPDX-License-Identifier: BSL-1.0

#undef NDEBUG

#include <etl/bitset.hpp>
#include <etl/cassert.hpp>

auto main() -> int
{
    auto bits = etl::bitset<8>();
    assert(bits.none() == true);
    assert(bits.any() == false);
    assert(bits.all() == false);
    assert(bits.test(0) == false);

    bits.set(0);
    assert(bits.test(0) == true);
    assert(bits.count() == 1);

    bits.set(1);
    assert(bits.test(1) == true);
    assert(bits.count() == 2);

    bits.reset(1);
    assert(bits.test(1) == false);

    bits.reset();
    assert(bits.test(0) == false);

    etl::bitset<8>::reference ref = bits[0];
    assert(ref == false);
    assert(~ref == true);

    ref = true;
    assert(ref == true);
    assert(~ref == false);

    ref.flip();
    assert(ref == false);
    assert(~ref == true);

    return 0;
}
