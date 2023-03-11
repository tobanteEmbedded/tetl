/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_SIMD_TINYSIMD_HPP
#define TETL_SIMD_TINYSIMD_HPP

#include "etl/_algorithm/copy.hpp"
#include "etl/_algorithm/fill.hpp"
#include "etl/_array/array.hpp"
#include "etl/_cmath/fma.hpp"
#include "etl/_cstdint/int_t.hpp"
#include "etl/_cstdint/uint_t.hpp"
#include "etl/_functional/divides.hpp"
#include "etl/_functional/minus.hpp"
#include "etl/_functional/multiplies.hpp"
#include "etl/_functional/plus.hpp"
#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_type_traits/is_void.hpp"

// #include <immintrin.h>

namespace etl::tinysimd {

template <typename I>
struct simd_traits {
    static constexpr unsigned width = 0;
    using scalar_type               = void;
    using vector_type               = void;
};

template <typename I>
struct fallback {
    static constexpr unsigned width = simd_traits<I>::width;
    using scalar_type               = typename simd_traits<I>::scalar_type;
    using vector_type               = typename simd_traits<I>::vector_type;
    using store                     = scalar_type[width];

    template <typename Op>
    static constexpr auto op_2(vector_type u, vector_type v, Op op)
    {
        store a, b, r;
        I::copy_to(u, a);
        I::copy_to(v, b);
        for (unsigned i = 0; i < width; ++i) r[i] = op(a[i], b[i]);
        return I::copy_from(r);
    }

    template <typename Op>
    static constexpr auto op_3(vector_type u, vector_type v, vector_type w, Op op)
    {
        store a, b, c, r;
        I::copy_to(u, a);
        I::copy_to(v, b);
        I::copy_to(w, c);
        for (unsigned i = 0; i < width; ++i) r[i] = op(a[i], b[i], c[i]);
        return I::copy_from(r);
    }

    static constexpr auto broadcast(scalar_type x) -> vector_type
    {
        store a;
        fill(begin(a), end(a), x);
        return I::copy_from(a);
    }

    static constexpr auto element(vector_type u, unsigned i) -> scalar_type
    {
        store a;
        I::copy_to(u, a);
        return a[i];
    }

    static constexpr auto set_element(vector_type& u, unsigned i, scalar_type const& x) -> void
    {
        store a;
        I::copy_to(u, a);
        a[i] = x;
        u    = I::copy_from(a);
    }

    static constexpr auto add(vector_type u, vector_type v) { return op_2(u, v, plus<> {}); }
    static constexpr auto sub(vector_type u, vector_type v) { return op_2(u, v, minus<> {}); }
    static constexpr auto mul(vector_type u, vector_type v) { return op_2(u, v, multiplies<> {}); }
    static constexpr auto div(vector_type u, vector_type v) { return op_2(u, v, divides<> {}); }
    static constexpr auto fma(vector_type u, vector_type v, vector_type w) { return op_3(u, v, w, etl::fma); }
};

template <typename T, unsigned N>
struct generic;

namespace abi {

template <typename T, unsigned N>
struct generic {
    using type = ::etl::tinysimd::generic<T, N>;
};

} // namespace abi

template <typename T, unsigned N>
struct simd_traits<generic<T, N>> {
    static constexpr unsigned width = N;
    using scalar_type               = T;
    using vector_type               = array<T, N>;
};

template <typename T, unsigned N>
struct generic : fallback<generic<T, N>> {
    using array = array<T, N>;

    static void copy_to(array v, T* p) { copy(begin(v), end(v), p); }
    static array copy_from(T const* p)
    {
        array v;
        copy(p, p + N, v.data());
        return v;
    }
    static T element(array v, unsigned i) { return v[i]; }
    static void set_element(array& v, unsigned i, T const& x) { v[i] = x; }
};

namespace abi {

template <typename T, unsigned N>
struct avx2 {
    using type = void;
};

} // namespace abi

#if defined(__AVX2__) && defined(__FMA__)

struct avx2_float64_x4;
template <>
struct simd_traits<avx2_float64_x4> {
    static constexpr unsigned width = 4;
    using scalar_type               = double;
    using vector_type               = __m256d;
};

struct avx2_int32_x4;
template <>
struct simd_traits<avx2_int32_x4> {
    static constexpr unsigned width = 4;
    using scalar_type               = int32_t;
    using vector_type               = __m128i;
};

namespace abi {

template <>
struct avx2<int32_t, 4> {
    using type = avx2_int32_x4;
};
template <>
struct avx2<double, 4> {
    using type = avx2_float64_x4;
};

} // namespace abi

struct avx2_float64_x4 : fallback<avx2_float64_x4> {
    static auto copy_to(__m256d v, double* p) -> void { _mm256_storeu_pd(p, v); }
    static auto copy_from(double const* p) -> __m256d { return _mm256_loadu_pd(p); }
    static auto broadcast(double v) -> __m256d { return _mm256_set1_pd(v); }

    static auto add(__m256d a, __m256d b) -> __m256d { return _mm256_add_pd(a, b); }
    static auto mul(__m256d a, __m256d b) -> __m256d { return _mm256_mul_pd(a, b); }
    static auto div(__m256d a, __m256d b) -> __m256d { return _mm256_div_pd(a, b); }
    static auto fma(__m256d u, __m256d v, __m256d w) -> __m256d { return _mm256_fmadd_pd(u, v, w); }
};

struct avx2_int32_x4 : fallback<avx2_int32_x4> {
    static auto copy_to(__m128i v, int32_t* p) -> void { _mm_storeu_si128((__m128i*)p, v); }
    static auto copy_from(int32_t const* p) -> __m128i { return _mm_loadu_si128((__m128i const*)p); }
    static auto broadcast(int32_t v) -> __m128i { return _mm_set1_epi32(v); }

    static auto add(__m128i a, __m128i b) -> __m128i { return _mm_add_epi32(a, b); }
    static auto mul(__m128i a, __m128i b) -> __m128i { return _mm_mullo_epi32(a, b); }
    static auto fma(__m128i u, __m128i v, __m128i w) -> __m128i { return add(mul(u, v), w); }
};

#endif // defined(__AVX2__) && defined(__FMA__)

template <typename...>
struct first_not_void_of {
    using type = void;
};

template <typename... Rest>
struct first_not_void_of<void, Rest...> {
    using type = typename first_not_void_of<Rest...>::type;
};

template <typename T, typename... Rest>
struct first_not_void_of<T, Rest...> {
    using type = T;
};

namespace abi {

template <typename T, unsigned N>
struct default_abi {
    using type = typename first_not_void_of< //
        typename avx2<T, N>::type,           //
        typename generic<T, N>::type         //
        >::type;
};

} // namespace abi

template <typename I>
struct simd_wrap {
    using scalar_type               = typename simd_traits<I>::scalar_type;
    using vector_type               = typename simd_traits<I>::vector_type;
    static constexpr unsigned width = simd_traits<I>::width;

    struct element_proxy {
        vector_type* vptr;
        int i;

        element_proxy operator=(scalar_type x)
        {
            I::set_element(*vptr, i, x);
            return *this;
        }
        operator scalar_type() const { return I::element(*vptr, i); }
    };

    simd_wrap()                       = default;
    simd_wrap(simd_wrap const& other) = default;
    simd_wrap(scalar_type x) : value_(I::broadcast(x)) { }
    simd_wrap(const scalar_type (&a)[width]) : value_(I::copy_from(a)) { }
    explicit simd_wrap(scalar_type const* p) : value_(I::copy_from(p)) { }

    simd_wrap& operator=(simd_wrap const& other) = default;
    simd_wrap& operator=(scalar_type const& x)
    {
        value_ = I::broadcast(x);
        return *this;
    }

    void copy_to(scalar_type* p) const;

    [[nodiscard]] friend auto operator+(simd_wrap const& a, simd_wrap const& b) -> simd_wrap;
    [[nodiscard]] friend auto operator*(simd_wrap const& a, simd_wrap const& b) -> simd_wrap;
    [[nodiscard]] friend auto operator/(simd_wrap const& a, simd_wrap const& b) -> simd_wrap;

    [[nodiscard]] friend auto fma(simd_wrap const& a, simd_wrap const& b, simd_wrap const& c) -> simd_wrap;

    auto operator+=(simd_wrap const& a) -> simd_wrap&;
    auto operator*=(simd_wrap const& a) -> simd_wrap&;

    auto operator[](int i) -> element_proxy;
    auto operator[](int i) const -> scalar_type;

private:
    static_assert(!is_void<I>::value, "unsupported SIMD ABI");

    vector_type value_;

    static auto wrap(vector_type const& v) -> simd_wrap
    {
        simd_wrap s;
        s.value_ = v;
        return s;
    }
};

template <typename I>
auto simd_wrap<I>::copy_to(scalar_type* p) const -> void
{
    I::copy_to(value_, p);
}

template <typename I>
auto operator+(simd_wrap<I> const& a, simd_wrap<I> const& b) -> simd_wrap<I>
{
    return wrap(I::add(a.value_, b.value_));
}

template <typename I>
auto operator*(simd_wrap<I> const& a, simd_wrap<I> const& b) -> simd_wrap<I>
{
    return wrap(I::mul(a.value_, b.value_));
}

template <typename I>
auto operator/(simd_wrap<I> const& a, simd_wrap<I> const& b) -> simd_wrap<I>
{
    return wrap(I::div(a.value_, b.value_));
}

template <typename I>
auto fma(simd_wrap<I> const& a, simd_wrap<I> const& b, simd_wrap<I> const& c) -> simd_wrap<I>
{
    return wrap(I::fma(a.value_, b.value_, c.value_));
}

template <typename I>
auto simd_wrap<I>::operator+=(simd_wrap<I> const& a) -> simd_wrap<I>&
{
    value_ = I::add(value_, a.value_);
    return *this;
}

template <typename I>
auto simd_wrap<I>::operator*=(simd_wrap<I> const& a) -> simd_wrap<I>&
{
    value_ = I::mul(value_, a.value_);
    return *this;
}

template <typename I>
auto simd_wrap<I>::operator[](int i) -> element_proxy
{
    return element_proxy { &value_, i };
}

template <typename I>
auto simd_wrap<I>::operator[](int i) const -> scalar_type
{
    return I::element(value_, i);
}

template <typename V, unsigned N, template <typename, unsigned> class abi = abi::default_abi>
using simd = simd_wrap<typename abi<V, N>::type>;

} // namespace etl::tinysimd

#endif // TETL_SIMD_TINYSIMD_HPP
