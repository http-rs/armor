# armor
[![crates.io version][1]][2] [![build status][3]][4]
[![downloads][5]][6] [![docs.rs docs][7]][8]

HTTP Security Headers. Adapted from [helmetjs](https://helmetjs.github.io/).

- [Documentation][8]
- [Crates.io][2]
- [Releases][releases]

## Examples
__Basic usage__
```rust
let mut headers = http::HeaderMap::new();
armor::armor(&mut headers);
assert_eq!(headers["X-Content-Type-Options"], "nosniff");
assert_eq!(headers["X-XSS-Protection"], "1; mode=block");
```

## Installation
```sh
$ cargo add armor
```

## Safety
This crate uses ``#![deny(unsafe_code)]`` to ensure everything is implemented in
100% Safe Rust.

## Contributing
Want to join us? Check out our ["Contributing" guide][contributing] and take a
look at some of these issues:

- [Issues labeled "good first issue"][good-first-issue]
- [Issues labeled "help wanted"][help-wanted]

## References
None.

## License
[MIT](./LICENSE-MIT) OR [Apache-2.0](./LICENSE-APACHE)

[1]: https://img.shields.io/crates/v/armor.svg?style=flat-square
[2]: https://crates.io/crates/armor
[3]: https://img.shields.io/travis/rustasync/armor/master.svg?style=flat-square
[4]: https://travis-ci.org/rustasync/armor
[5]: https://img.shields.io/crates/d/armor.svg?style=flat-square
[6]: https://crates.io/crates/armor
[7]: https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square
[8]: https://docs.rs/armor

[releases]: https://github.com/rustasync/armor/releases
[contributing]: https://github.com/rustasync/armor/blob/master.github/CONTRIBUTING.md
[good-first-issue]: https://github.com/rustasync/armor/labels/good%20first%20issue
[help-wanted]: https://github.com/rustasync/armor/labels/help%20wanted
