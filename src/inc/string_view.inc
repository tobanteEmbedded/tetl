export namespace etl {

using etl::basic_string_view;
using etl::operator==;
using etl::operator!=;
using etl::operator<;
using etl::operator<=;
using etl::operator>;
using etl::operator>=;
using etl::string_view;
using etl::swap;
using etl::u16string_view;
using etl::u32string_view;
using etl::u8string_view;
using etl::wstring_view;

namespace ranges {
using etl::ranges::enable_borrowed_range;
} // namespace ranges

inline namespace literals {
inline namespace string_view_literals {

using etl::literals::string_view_literals::operator""_sv;

} // namespace string_view_literals
} // namespace literals

} // namespace etl
