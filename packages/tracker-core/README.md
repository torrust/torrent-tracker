# BitTorrent Core Tracker library

A library with the core functionality needed to implement a BitTorrent tracker.

You usually don’t need to use this library directly. Instead, you should use the [Torrust Tracker](https://github.com/torrust/torrust-tracker). If you want to build your own tracker, you can use this library as the core functionality. In that case, you should add the delivery layer (HTTP or UDP) on top of this library.

> **Disclaimer**: This library is actively under development. We’re currently extracting and refining common types from the[Torrust Tracker](https://github.com/torrust/torrust-tracker) to make them available to the BitTorrent community in Rust. While these types are functional, they are not yet ready for use in production or third-party projects.

## Documentation

[Crate documentation](https://docs.rs/bittorrent-tracker-core).

## License

The project is licensed under the terms of the [GNU AFFERO GENERAL PUBLIC LICENSE](./LICENSE).
