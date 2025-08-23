export namespace etl {

using etl::bad_variant_access;
using etl::get;
using etl::get_if;
using etl::holds_alternative;
using etl::monostate;
using etl::unchecked_get;
using etl::variant;
using etl::variant_alternative;
using etl::variant_alternative_t;
using etl::variant_size;
using etl::variant_size_v;
using etl::visit;
using etl::visit_with_index;
using etl::operator==;
using etl::operator!=;

// Non-standard extensions
using etl::overload;
using etl::uninitialized_union;
using etl::variadic_union;

namespace detail {
using etl::detail::variant_alternative_selector_t;
}

} // namespace etl
