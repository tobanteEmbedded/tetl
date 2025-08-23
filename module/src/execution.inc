export namespace etl {

using etl::is_execution_policy;
using etl::is_execution_policy_v;

namespace execution {

using etl::execution::sequenced_policy;
using etl::execution::unsequenced_policy;

} // namespace execution

// Non-standard extensions
using etl::execution_policy;

} // namespace etl
