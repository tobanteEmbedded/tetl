// SPDX-License-Identifier: BSL-1.0

#include <etl/complex.hpp>

#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // traits
    CHECK(sizeof(etl::complex<T>) == sizeof(T) * 2);
    CHECK_SAME_TYPE(typename etl::complex<T>::value_type, T);
    CHECK(etl::is_trivially_copyable_v<etl::complex<T>>);

    // construct
    auto z1 = etl::complex<T>{};
    CHECK(z1.real() == T(0));
    CHECK(z1.imag() == T(0));

    auto z2 = etl::complex<T>{T(1)};
    CHECK(z2.real() == T(1));
    CHECK(z2.imag() == T(0));

    auto z3 = etl::complex<T>{T(1), T(2)};
    CHECK(z3.real() == T(1));
    CHECK(z3.imag() == T(2));

    {
        // from complex<U>
        auto z = etl::complex<T>(etl::complex<signed char>{1, 2});
        CHECK(z.real() == T(1));
        CHECK(z.imag() == T(2));

        z = T(4);
        CHECK(z.real() == T(4));
        CHECK(z.imag() == T(0));
    }

    z1 = z2;
    CHECK(z1.real() == T(1));
    CHECK(z1.imag() == T(0));
    CHECK(etl::real(z1) == T(1));
    CHECK(etl::imag(z1) == T(0));
    CHECK(real(z1) == T(1)); // ADL
    CHECK(imag(z1) == T(0)); // ADL

    z1 *= T(2);
    CHECK(z1.real() == T(2));
    CHECK(z1.imag() == T(0));

    z1.real(T(1));
    z1.imag(T(2));
    CHECK(z1.real() == T(1));
    CHECK(z1.imag() == T(2));

    // unary +
    z1 = +z1;
    CHECK(z1.real() == T(1));
    CHECK(z1.imag() == T(2));

    // unary -
    z1 = -z1;
    CHECK(z1.real() == T(-1));
    CHECK(z1.imag() == T(-2));

    // unary -
    z1 = -z1;
    CHECK(z1.real() == T(1));
    CHECK(z1.imag() == T(2));

    // operator+
    auto sum = z1 + z1;
    CHECK(sum.real() == T(2));
    CHECK(sum.imag() == T(4));

    // operator-
    auto diff = z1 - sum;
    CHECK(diff.real() == T(-1));
    CHECK(diff.imag() == T(-2));

    // scaled_mul
    auto scaledMul = diff * T(2);
    CHECK(scaledMul.real() == T(-2));
    CHECK(scaledMul.imag() == T(-4));

    // scaled_div
    auto scaledDiv = scaledMul / T(2);
    CHECK(scaledDiv.real() == T(-1));
    CHECK(scaledDiv.imag() == T(-2));

    // operator-=
    {
        auto z = etl::complex<T>{T(1), T(2)};
        z -= T(1);
        CHECK(z.real() == T(0));
    }

    // operator+
    {
        auto z = etl::complex<T>{T(1), T(2)};
        CHECK((z + T(1)) == etl::complex{T(2), T(2)});
        CHECK((z + T(3)) == etl::complex{T(4), T(2)});
        CHECK((T(1) + z) == etl::complex{T(2), T(2)});
    }

    // operator-
    {
        auto z = etl::complex<T>{T(1), T(2)};
        CHECK((z - T(1)) == etl::complex{T(0), T(2)});
        CHECK((z - T(3)) == etl::complex{T(-2), T(2)});
        CHECK((T(1) - z) == etl::complex{T(0), T(-2)});
    }

    // compare
    {
        CHECK(etl::complex<T>{} == etl::complex<T>{});
        CHECK(etl::complex<T>{T(1)} == etl::complex<T>{T(1)});
        CHECK(etl::complex<T>{T(1), T(2)} == etl::complex<T>{T(1), T(2)});

        CHECK(etl::complex<T>{T(1), T(2)} != etl::complex<T>{T(1), T(3)});
        CHECK(etl::complex<T>{T(2), T(2)} != etl::complex<T>{T(1), T(2)});

        CHECK(etl::complex<T>{} == T(0));
        CHECK(etl::complex<T>{T(1)} == T(1));
        CHECK(etl::complex<T>{T(1)} != T(2));

        CHECK(T(0) == etl::complex<T>{});
        CHECK(T(1) == etl::complex<T>{T(1)});
    }

    // udl
    {
        using namespace etl::literals;

        auto f = 3.0_if;
        CHECK(f.real() == 0.0F);
        CHECK(f.imag() == 3.0F);

        auto d = 3.0_i;
        CHECK(d.real() == 0.0);
        CHECK(d.imag() == 3.0);

        auto ld = 3.0_il;
        CHECK(ld.real() == 0.0L);
        CHECK(ld.imag() == 3.0L);

        auto fi = 2_if;
        CHECK(fi.real() == 0.0F);
        CHECK(fi.imag() == 2.0F);

        auto di = 2_i;
        CHECK(di.real() == 0.0);
        CHECK(di.imag() == 2.0);

        auto ldi = 2_il;
        CHECK(ldi.real() == 0.0L);
        CHECK(ldi.imag() == 2.0L);
    }
    {
        using namespace etl::complex_literals;

        auto f = 3.0_if;
        CHECK(f.real() == 0.0F);
        CHECK(f.imag() == 3.0F);

        auto d = 3.0_i;
        CHECK(d.real() == 0.0);
        CHECK(d.imag() == 3.0);

        auto ld = 3.0_il;
        CHECK(ld.real() == 0.0L);
        CHECK(ld.imag() == 3.0L);

        auto fi = 2_if;
        CHECK(fi.real() == 0.0F);
        CHECK(fi.imag() == 2.0F);

        auto di = 2_i;
        CHECK(di.real() == 0.0);
        CHECK(di.imag() == 2.0);

        auto ldi = 2_il;
        CHECK(ldi.real() == 0.0L);
        CHECK(ldi.imag() == 2.0L);
    }
    {
        using namespace etl::literals::complex_literals;

        auto f = 3.0_if;
        CHECK(f.real() == 0.0F);
        CHECK(f.imag() == 3.0F);

        auto d = 3.0_i;
        CHECK(d.real() == 0.0);
        CHECK(d.imag() == 3.0);

        auto ld = 3.0_il;
        CHECK(ld.real() == 0.0L);
        CHECK(ld.imag() == 3.0L);

        auto fi = 2_if;
        CHECK(fi.real() == 0.0F);
        CHECK(fi.imag() == 2.0F);

        auto di = 2_i;
        CHECK(di.real() == 0.0);
        CHECK(di.imag() == 2.0);

        auto ldi = 2_il;
        CHECK(ldi.real() == 0.0L);
        CHECK(ldi.imag() == 2.0L);
    }

    // tuple protocol
    CHECK(etl::tuple_size_v<etl::complex<T>> == 2);
    CHECK_SAME_TYPE(etl::tuple_element_t<0, etl::complex<T>>, T);
    CHECK_SAME_TYPE(etl::tuple_element_t<1, etl::complex<T>>, T);

    auto z = etl::complex{T(1), T(2)};

    CHECK_SAME_TYPE(decltype(etl::get<0>(z)), T&);
    CHECK_SAME_TYPE(decltype(etl::get<0>(etl::as_const(z))), T const&);
    CHECK_SAME_TYPE(decltype(etl::get<0>(etl::move(z))), T&&);
    CHECK_SAME_TYPE(decltype(etl::get<1>(z)), T&);
    CHECK_SAME_TYPE(decltype(etl::get<1>(etl::as_const(z))), T const&);
    CHECK_SAME_TYPE(decltype(etl::get<1>(etl::move(z))), T&&);

    CHECK_NOEXCEPT(etl::get<0>(z));
    CHECK_NOEXCEPT(etl::get<0>(etl::as_const(z)));
    CHECK_NOEXCEPT(etl::get<0>(etl::move(z)));
    CHECK_NOEXCEPT(etl::get<1>(z));
    CHECK_NOEXCEPT(etl::get<1>(etl::as_const(z)));
    CHECK_NOEXCEPT(etl::get<1>(etl::move(z)));

    CHECK(etl::get<0>(z) == T(1));
    CHECK(etl::get<1>(z) == T(2));
    CHECK(etl::get<0>(etl::as_const(z)) == T(1));
    CHECK(etl::get<1>(etl::as_const(z)) == T(2));
    CHECK(etl::get<0>(etl::complex{T(1), T(2)}) == T(1));
    CHECK(etl::get<1>(etl::complex{T(1), T(2)}) == T(2));

    CHECK_SAME_TYPE(decltype(get<0>(z)), T&);                         // ADL
    CHECK_SAME_TYPE(decltype(get<0>(etl::as_const(z))), T const&);    // ADL
    CHECK_SAME_TYPE(decltype(get<0>(etl::complex{T(1), T(2)})), T&&); // ADL
    CHECK_SAME_TYPE(decltype(get<1>(z)), T&);                         // ADL
    CHECK_SAME_TYPE(decltype(get<1>(etl::as_const(z))), T const&);    // ADL
    CHECK_SAME_TYPE(decltype(get<1>(etl::complex{T(1), T(2)})), T&&); // ADL

    CHECK(get<0>(z) == T(1));                        // ADL
    CHECK(get<1>(z) == T(2));                        // ADL
    CHECK(get<0>(etl::as_const(z)) == T(1));         // ADL
    CHECK(get<1>(etl::as_const(z)) == T(2));         // ADL
    CHECK(get<0>(etl::complex{T(1), T(2)}) == T(1)); // ADL
    CHECK(get<1>(etl::complex{T(1), T(2)}) == T(2)); // ADL

    // access
    CHECK(etl::conj(T(12)) == T(12));
    CHECK(etl::real(T(12)) == T(12));
    CHECK(etl::imag(T(12)) == T(0));

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
