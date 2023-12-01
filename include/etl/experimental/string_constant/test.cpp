#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/string_view.hpp>

template <typename T, etl::size_t Size>
using c_array = T[Size];

using string_id = etl::uint32_t;

template <typename StringType>
extern auto catalog() -> string_id;

template <typename StringType>
inline auto catalog(StringType) -> string_id
{
    return catalog<StringType>();
}

template <typename CharT, CharT... chars>
struct string_constant {
private:
    using This       = string_constant<CharT, chars...>;
    using StringView = etl::basic_string_view<CharT>;

    static constexpr etl::array<CharT, sizeof...(chars)> storage {chars...};
};

template <typename T, T... chars>
constexpr auto operator""_sc()
{
    return string_constant<T, chars...> {};
}

template <auto Str>
consteval auto to_string_constant()
{
    return []<etl::size_t... idx>(etl::index_sequence<idx...>) {
        return string_constant<char, etl::get<idx>(Str)...> {};
    }(etl::make_index_sequence<etl::size(Str)> {});
}

#define TETL_STRING_CONSTANT(str) to_string_constant<etl::to_array((str))>()

auto bar()
{
    constexpr auto x = etl::to_array("test");
    static_assert(x.size() == 5);

    catalog("test"_sc);
    catalog("bar"_sc);
    catalog(TETL_STRING_CONSTANT("tobias hienzsch"));
}
