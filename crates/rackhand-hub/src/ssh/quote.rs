//! POSIX quoting (7.3.7): each argument in single quotes, a `'` written as `'\''`, joined with spaces. The user's
//! `/bin/sh` on the machine then sees exactly the argument list.

pub fn quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

pub fn join(args: &[String]) -> String {
    args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
}
