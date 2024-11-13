# Torrust Tracker Client

A collection of console clients to make requests to BitTorrent trackers.

> **Disclaimer**: This project is actively under development. We’re currently extracting and refining common functionality from the[Torrust Tracker](https://github.com/torrust/torrust-tracker) to make it available to the BitTorrent community in Rust. While these tools are functional, they are not yet ready for use in production or third-party projects.

There are currently three console clients available:

- UDP Client
- HTTP Client
- Tracker Checker

> **Notice**: [Console apps are planned to be merge into a single tracker client in the short-term](https://github.com/torrust/torrust-tracker/discussions/660).

## UDP Client

`Announce` request:

```text
cargo run --bin udp_tracker_client announce udp://127.0.0.1:6969 9c38422213e30bff212b30c360d26f9a02136422 | jq
```

`Announce` response:

```json
{
  "AnnounceIpv4": {
    "transaction_id": -888840697,
    "announce_interval": 120,
    "leechers": 0,
    "seeders": 1,
    "peers": []
  }
}
```

`Scrape` request:

```text
cargo run --bin udp_tracker_client scrape udp://127.0.0.1:6969 9c38422213e30bff212b30c360d26f9a02136422 | jq
```

`Scrape` response:

```json
{
  "Scrape": {
    "transaction_id": -888840697,
    "torrent_stats": [
      {
        "seeders": 1,
        "completed": 0,
        "leechers": 0
      }
    ]
  }
}
```

## HTTP Client

`Announce` request:

```text
cargo run --bin http_tracker_client announce http://127.0.0.1:7070 9c38422213e30bff212b30c360d26f9a02136422 | jq
```

`Announce` response:

```json
{
  "complete": 1,
  "incomplete": 0,
  "interval": 120,
  "min interval": 120,
  "peers": []
}
```

`Scrape` request:

```text
 cargo run --bin http_tracker_client scrape http://127.0.0.1:7070 9c38422213e30bff212b30c360d26f9a02136422 | jq
```

`Scrape` response:

```json
{
  "9c38422213e30bff212b30c360d26f9a02136422": {
    "complete": 1,
    "downloaded": 1,
    "incomplete": 0
  }
}
```

## Tracker Checker

The Tracker Checker is a tool to check the health of a list of trackers.

```console
TORRUST_CHECKER_CONFIG='{
     "udp_trackers": ["127.0.0.1:6969"],
     "http_trackers": ["http://127.0.0.1:7070"],
     "health_checks": ["http://127.0.0.1:1212/api/health_check"]
 }' cargo run --bin tracker_checker
```

Output:

```json
[
  {
    "Udp": {
      "Ok": {
        "remote_addr": "127.0.0.1:6969",
        "results": [
          [
            "Setup",
            {
              "Ok": null
            }
          ],
          [
            "Connect",
            {
              "Ok": null
            }
          ],
          [
            "Announce",
            {
              "Ok": null
            }
          ],
          [
            "Scrape",
            {
              "Ok": null
            }
          ]
        ]
      }
    }
  },
  {
    "Health": {
      "Ok": {
        "url": "http://127.0.0.1:1212/api/health_check",
        "result": {
          "Ok": "200 OK"
        }
      }
    }
  },
  {
    "Http": {
      "Ok": {
        "url": "http://127.0.0.1:7070/",
        "results": [
          [
            "Announce",
            {
              "Ok": null
            }
          ],
          [
            "Scrape",
            {
              "Ok": null
            }
          ]
        ]
      }
    }
  }
]
```

## License

**Copyright (c) 2024 The Torrust Developers.**

This program is free software: you can redistribute it and/or modify it under the terms of the [GNU Lesser General Public License][LGPL_3_0] as published by the [Free Software Foundation][FSF], version 3.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU Lesser General Public License][LGPL_3_0] for more details.

You should have received a copy of the *GNU Lesser General Public License* along with this program. If not, see <https://www.gnu.org/licenses/>.

Some files include explicit copyright notices and/or license notices.

### Legacy Exception

For prosperity, versions of Torrust BitTorrent Tracker Client that are older than five years are automatically granted the [MIT-0][MIT_0] license in addition to the existing [LGPL-3.0-only][LGPL_3_0] license.

[LGPL_3_0]: ./LICENSE
[MIT_0]: ./docs/licenses/LICENSE-MIT_0
[FSF]: https://www.fsf.org/
