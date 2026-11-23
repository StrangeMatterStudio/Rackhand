//! Runs assistant jobs with a `Runner` (design 7.2, Operator; 7.3.5). An operator host joins one or more hubs with an
//! invite, keeps one connection to each, accepts the jobs they offer up to its limit, and runs each with a runner whose only
//! way to the hub is the MCP bridge. The job token stays in the operator: the bridge process the runner starts reaches
//! the hub only through a socket the operator serves, so the runner never sees a token.

pub mod bridge;
pub mod claude_code;
pub mod fake;
pub mod join;
pub mod run;
pub mod runner;
pub mod state;
