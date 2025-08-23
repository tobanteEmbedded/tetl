export namespace etl {

using etl::addressof;
using etl::align;
using etl::allocator_arg_t;
using etl::allocator_traits;
using etl::assume_aligned;
using etl::construct_at;
using etl::default_delete;
using etl::destroy;
using etl::destroy_at;
using etl::destroy_n;
using etl::pointer_traits;
using etl::to_address;
using etl::uninitialized_copy;
using etl::uninitialized_fill;
using etl::uninitialized_move;
using etl::uses_allocator;

namespace ranges {
using etl::ranges::construct_at;
using etl::ranges::destroy;
using etl::ranges::destroy_at;
} // namespace ranges

// Non-standard extensions
using etl::monotonic_allocator;
using etl::pointer_int_pair;
using etl::pointer_int_pair_info;
using etl::pointer_like_traits;
using etl::small_ptr;

} // namespace etl
