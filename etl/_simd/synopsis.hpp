
namespace etl::experimental {

inline namespace parallelism_v2 {

namespace simd_abi {
using scalar = /* see below */;
template <int N>
using fixed_size = /* see below */;
template <typename T>
inline constexpr int max_fixed_size = /* implementation-defined */;
template <typename T>
using compatible = /* implementation-defined */;
template <typename T>
using native = /* implementation-defined */;
template <typename T, size_t N, typename... Abis>
struct deduce {
    using type = /* see below */;
};
template <typename T, size_t N, typename... Abis>
using deduce_t = typename deduce<T, N, Abis...>::type;
} // namespace simd_abi

struct element_aligned_tag {
};
struct vector_aligned_tag {
};
template <size_t>
struct overaligned_tag {
};
inline constexpr element_aligned_tag element_aligned {};
inline constexpr vector_aligned_tag vector_aligned {};
template <size_t N>
inline constexpr overaligned_tag<N> overaligned {};

// 9.4, simd type traits
template <typename T>
struct is_abi_tag;

template <typename T>
inline constexpr bool is_abi_tag_v = is_abi_tag<T>::value;

template <typename T>
struct is_simd;

template <typename T>
inline constexpr bool is_simd_v = is_simd<T>::value;

template <typename T>
struct is_simd_mask;

template <typename T>
inline constexpr bool is_simd_mask_v = is_simd_mask<T>::value;

template <typename T>
struct is_simd_flag_type;

template <typename T>
inline constexpr bool is_simd_flag_type_v = is_simd_flag_type<T>::value;

template <typename T, typename Abi = simd_abi::compatible<T>>
struct simd_size;

template <typename T, typename Abi = simd_abi::compatible<T>>
inline constexpr size_t simd_size_v = simd_size<T, Abi>::value;

template <typename T, typename U = typename T::value_type>
struct memory_alignment;

template <typename T, typename U = typename T::value_type>
inline constexpr size_t memory_alignment_v = memory_alignment<T, U>::value;

template <typename T, typename V>
struct rebind_simd {
    using type = /* see below */;
};

template <typename T, typename V>
using rebind_simd_t = typename rebind_simd<T, V>::type;

template <int N, typename V>
struct resize_simd {
    using type = /* see below */;
};

template <int N, typename V>
using resize_simd_t = typename resize_simd<N, V>::type;

// 9.6, typename template simd
template <typename T, typename Abi = simd_abi::compatible<T>>
struct simd;
template <typename T>
using native_simd = simd<T, simd_abi::native<T>>;
template <typename T, int N>
using fixed_size_simd = simd<T, simd_abi::fixed_size<N>>;

// 9.8, typename template simd_mask
template <typename T, typename Abi = simd_abi::compatible<T>>
struct simd_mask;
template <typename T>
using native_simd_mask = simd_mask<T, simd_abi::native<T>>;
template <typename T, int N>
using fixed_size_simd_mask = simd_mask<T, simd_abi::fixed_size<N>>;

// 9.7.5, Casts
template <typename T, typename U, typename Abi>
auto simd_cast(simd<U, Abi> const&) noexcept -> /* see below */;

template <typename T, typename U, typename Abi>
auto static_simd_cast(simd<U, Abi> const&) noexcept -> /* see below */;

template <typename T, typename Abi>
auto to_fixed_size(simd<T, Abi> const&) noexcept -> fixed_size_simd<T, simd_size_v<T, Abi>>;
template <typename T, typename Abi>
auto to_fixed_size(simd_mask<T, Abi> const&) noexcept -> fixed_size_simd_mask<T, simd_size_v<T, Abi>>;

template <typename T, int N>
auto to_native(fixed_size_simd<T, N> const&) noexcept -> native_simd<T>;
template <typename T, int N>
auto to_native(fixed_size_simd_mask<T, N> const&) noexcept -> native_simd_mask<T>;

template <typename T, int N>
auto to_compatible(fixed_size_simd<T, N> const&) noexcept -> simd<T>;
template <typename T, int N>
auto to_compatible(fixed_size_simd_mask<T, N> const&) noexcept -> simd_mask<T>;

template <size_t... Sizes, typename T, typename Abi>
auto split(simd<T, Abi> const&) noexcept -> tuple<simd<T, simd_abi::deduce_t<T, Sizes>>...>;
template <size_t... Sizes, typename T, typename Abi>
auto split(simd_mask<T, Abi> const&) noexcept -> tuple<simd_mask<T, simd_mask_abi::deduce_t<T, Sizes>>...>;
template <typename V, typename Abi>
auto split(const simd<typename V::value_type, Abi>&) noexcept
    -> array<V, simd_size_v<typename V::value_type, Abi> / V::size()>;
template <typename V, typename Abi>
auto split(simd_mask<typename V::simd_type::value_type, Abi> const&) noexcept
    -> array<V, simd_size_v<typename V::simd_type::value_type, Abi> / V::size()>;

template <size_t N, typename T, typename A>
auto split_by(const simd<T, A>& x) noexcept -> array<resize_simd<simd_size_v<T, A> / N, simd<T, A>>, N>;
template <size_t N, typename T, typename A>
auto split_by(const simd_mask<T, A>& x) noexcept -> array<resize_simd<simd_size_v<T, A> / N, simd_mask<T, A>>, N>;

template <typename T, typename... Abis>
auto concat(const simd<T, Abis>&...) noexcept -> simd<T, simd_abi::deduce_t<T, (simd_size_v<T, Abis> + ...)>>;
template <typename T, typename... Abis>
auto concat(const simd_mask<T, Abis>&...) noexcept -> simd_mask<T, simd_abi::deduce_t<T, (simd_size_v<T, Abis> + ...)>>;
template <typename T, typename Abi, size_t N>
auto concat(array<simd<T, Abi>, N> const& arr) noexcept -> resize_simd<simd_size_v<T, Abi> * N, simd<T, Abi>>;
template <typename T, typename Abi, size_t N>
auto concat(array<simd_mask<T, Abi>, N> const& arr) noexcept -> resize_simd<simd_size_v<T, Abi> * N, simd_mask<T, Abi>>;

// 9.9.4, Reductions
template <typename T, typename Abi>
auto all_of(simd_mask<T, Abi> const&) noexcept -> bool;

template <typename T, typename Abi>
auto any_of(simd_mask<T, Abi> const&) noexcept -> bool;

template <typename T, typename Abi>
auto none_of(simd_mask<T, Abi> const&) noexcept -> bool;

template <typename T, typename Abi>
auto some_of(simd_mask<T, Abi> const&) noexcept -> bool;

template <typename T, typename Abi>
auto popcount(simd_mask<T, Abi> const&) noexcept -> int;

template <typename T, typename Abi>
auto find_first_set(simd_mask<T, Abi> const&) -> int;

template <typename T, typename Abi>
auto find_last_set(simd_mask<T, Abi> const&) -> int;

auto all_of(T) noexcept -> bool;
auto any_of(T) noexcept -> bool;
auto none_of(T) noexcept -> bool;
auto some_of(T) noexcept -> bool;
auto popcount(T) noexcept -> int;
auto find_first_set(T) -> int;
auto find_last_set(T) -> int;

// 9.5, Where expression typename templates
template <typename M, typename T>
struct const_where_expression;
template <typename M, typename T>
struct where_expression;

// 9.9.5, Where functions
template <typename T, typename Abi>
auto where(typename simd<T, Abi>::mask_type const&, simd<T, Abi>&) noexcept
    -> where_expression<simd_mask<T, Abi>, simd<T, Abi>>;
template <typename T, typename Abi>
auto where(typename simd<T, Abi>::mask_type const&, simd<T, Abi> const&) noexcept
    -> const_where_expression<simd_mask<T, Abi>, simd<T, Abi>>;
template <typename T, typename Abi>
auto where(type_identity_t<simd_mask<T, Abit>> const&, simd_mask<T, Abi>&) noexcept
    -> where_expression<simd_mask<T, Abi>, simd_mask<T, Abi>>;
template <typename T, typename Abi>
auto where(type_identity_t<simd_mask<T, Abit>> const&, simd_mask<T, Abi> const&) noexcept
    -> const_where_expression<simd_mask<T, Abi>, simd_mask<T, Abi>>;
template <typename T>
auto where(/* see below */ k, T& d) noexcept -> where_expression<bool, T>;
template <typename T>
auto where(/* see below */ k, T const& d) noexcept -> const_where_expression<bool, T>;

// 9.7.4, Reductions
template <typename T, typename Abi, typename BinaryOperation = plus<>>
auto reduce(simd<T, Abi> const&, BinaryOperation = {}) -> T;
template <typename M, typename V, typename BinaryOperation>
auto reduce(const_where_expression<M, V> const& x, typename V::value_type identity_element, BinaryOperation binary_op)
    -> typename V::value_type;
template <typename M, typename V>
auto reduce(const_where_expression<M, V> const& x, plus<> binary_op = {}) noexcept -> typename V::value_type;
template <typename M, typename V>
auto reduce(const_where_expression<M, V> const& x, multiplies<> binary_op) noexcept -> typename V::value_type;
template <typename M, typename V>
auto reduce(const_where_expression<M, V> const& x, bit_and<> binary_op) noexcept -> typename V::value_type;
template <typename M, typename V>
auto reduce(const_where_expression<M, V> const& x, bit_or<> binary_op) noexcept -> typename V::value_type;
template <typename M, typename V>
auto reduce(const_where_expression<M, V> const& x, bit_xor<> binary_op) noexcept -> typename V::value_type;

template <typename T, typename Abi>
auto hmin(simd<T, abi> const&) noexcept -> T;
template <typename M, typename V>
auto hmin(const_where_expression<M, V> const&) noexcept -> typename V::value_type;

template <typename T, typename Abi>
auto hmax(simd<T, abi> const&) noexcept -> T;
template <typename M, typename V>
auto hmax(const_where_expression<M, V> const&) noexcept -> typename V::value_type;

// 9.7.6, Algorithms
template <typename T, typename Abi>
auto min(simd<T, Abi> const& a, simd<T, Abi> const& b) noexcept -> simd<T, Abi>;

template <typename T, typename Abi>
auto max(simd<T, Abi> const& a, simd<T, Abi> const& b) noexcept -> simd<T, Abi>;

template <typename T, typename Abi>
auto minmax(simd<T, Abi> const& a, simd<T, Abi> const& b) noexcept -> pair<simd<T, Abi>, simd<T, Abi>>;

template <typename T, typename Abi>
auto clamp(simd<T, Abi> const& v, simd<T, Abi> const& lo, simd<T, Abi> const& hi) -> simd<T, Abi>;

} // namespace parallelism_v2
} // namespace etl::experimental