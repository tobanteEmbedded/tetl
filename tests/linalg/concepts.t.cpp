// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include "etl/cassert.hpp"
#include "etl/complex.hpp"
#include "testing/testing.hpp"

namespace ns {
struct my_complex {
    float real;
    float imag;
};

[[maybe_unused]] static auto real(my_complex const& cplx) -> float { return cplx.real; }

[[maybe_unused]] static auto imag(my_complex const& cplx) -> float { return cplx.imag; }

[[maybe_unused]] static auto conj(my_complex const& cplx) -> my_complex { return { cplx.real, -cplx.imag }; }

} // namespace ns

namespace detail = etl::linalg::detail;

static constexpr auto test_abs() -> bool
{
    assert(not detail::has_adl_abs<unsigned char>);
    assert(not detail::has_adl_abs<unsigned short>);
    assert(not detail::has_adl_abs<unsigned int>);
    assert(not detail::has_adl_abs<unsigned long>);
    assert(not detail::has_adl_abs<unsigned long long>);

    assert(detail::has_adl_abs<signed int>);
    assert(detail::has_adl_abs<signed long>);
    assert(detail::has_adl_abs<signed long long>);

    assert(detail::has_adl_abs<float>);
    assert(detail::has_adl_abs<double>);
    assert(detail::has_adl_abs<long double>);

    assert(not detail::has_adl_abs<ns::my_complex>); // no overload defined
    assert(detail::has_adl_abs<etl::complex<float>>);
    assert(detail::has_adl_abs<etl::complex<double>>);
    assert(detail::has_adl_abs<etl::complex<long double>>);

    return true;
}

static constexpr auto test_real() -> bool
{
    assert(not detail::has_adl_real<signed char>);
    assert(not detail::has_adl_real<short>);
    assert(not detail::has_adl_real<int>);
    assert(not detail::has_adl_real<long>);
    assert(not detail::has_adl_real<long long>);

    assert(not detail::has_adl_real<signed char>);
    assert(not detail::has_adl_real<unsigned short>);
    assert(not detail::has_adl_real<unsigned int>);
    assert(not detail::has_adl_real<unsigned long>);
    assert(not detail::has_adl_real<unsigned long long>);
    assert(not detail::has_adl_real<int>);

    assert(not detail::has_adl_real<float>);
    assert(not detail::has_adl_real<double>);
    assert(not detail::has_adl_real<long double>);

    assert(detail::has_adl_real<ns::my_complex>);
    assert(detail::has_adl_real<etl::complex<float>>);
    assert(detail::has_adl_real<etl::complex<double>>);
    assert(detail::has_adl_real<etl::complex<long double>>);

    return true;
}

static constexpr auto test_imag() -> bool
{
    assert(not detail::has_adl_imag<signed char>);
    assert(not detail::has_adl_imag<short>);
    assert(not detail::has_adl_imag<int>);
    assert(not detail::has_adl_imag<long>);
    assert(not detail::has_adl_imag<long long>);

    assert(not detail::has_adl_imag<signed char>);
    assert(not detail::has_adl_imag<unsigned short>);
    assert(not detail::has_adl_imag<unsigned int>);
    assert(not detail::has_adl_imag<unsigned long>);
    assert(not detail::has_adl_imag<unsigned long long>);
    assert(not detail::has_adl_imag<int>);

    assert(not detail::has_adl_imag<float>);
    assert(not detail::has_adl_imag<double>);
    assert(not detail::has_adl_imag<long double>);

    assert(detail::has_adl_imag<ns::my_complex>);
    assert(detail::has_adl_imag<etl::complex<float>>);
    assert(detail::has_adl_imag<etl::complex<double>>);
    assert(detail::has_adl_imag<etl::complex<long double>>);

    return true;
}

static constexpr auto test_conj() -> bool
{
    assert(not detail::has_adl_conj<signed char>);
    assert(not detail::has_adl_conj<short>);
    assert(not detail::has_adl_conj<int>);
    assert(not detail::has_adl_conj<long>);
    assert(not detail::has_adl_conj<long long>);

    assert(not detail::has_adl_conj<signed char>);
    assert(not detail::has_adl_conj<unsigned short>);
    assert(not detail::has_adl_conj<unsigned int>);
    assert(not detail::has_adl_conj<unsigned long>);
    assert(not detail::has_adl_conj<unsigned long long>);
    assert(not detail::has_adl_conj<int>);

    assert(not detail::has_adl_conj<float>);
    assert(not detail::has_adl_conj<double>);
    assert(not detail::has_adl_conj<long double>);

    assert(detail::has_adl_conj<ns::my_complex>);
    assert(detail::has_adl_conj<etl::complex<float>>);
    assert(detail::has_adl_conj<etl::complex<double>>);
    assert(detail::has_adl_conj<etl::complex<long double>>);

    return true;
}

static constexpr auto test_all() -> bool
{
    assert(test_abs());
    assert(test_real());
    assert(test_imag());
    assert(test_conj());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return EXIT_SUCCESS;
}
