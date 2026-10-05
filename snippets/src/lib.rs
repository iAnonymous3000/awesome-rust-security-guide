#![doc = include_str!("../../README.md")]
#![doc(test(attr(deny(warnings))))]
// Every Rust code block in the repository's README.md is a doctest of this
// crate, so `cargo test --doc --locked` checks them. Doctest names carry the
// README line number of each block's opening fence.
