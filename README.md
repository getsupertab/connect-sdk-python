# Supertab Connect SDK

Python SDK for Supertab Connect.

## Development

This project uses `hatchling` as the build backend.

See [DEVELOPMENT.md](DEVELOPMENT.md) for local setup, Git hooks, and CI-aligned development commands.

## Package Layout

```text
.
├── LICENSE
├── pyproject.toml
├── README.md
├── connect
│   ├── __init__.py
│   ├── common.py
│   ├── exceptions.py
│   ├── types.py
│   ├── url_pattern.py
│   ├── customer
│   │   ├── __init__.py
│   │   ├── content_matcher.py
│   │   ├── content_parser.py
│   │   └── token.py
│   └── merchant
│       ├── __init__.py
│       ├── jwks.py
│       └── license.py
├── examples
│   ├── obtain_license_token.py
│   └── obtain_and_verify_license_token.py
└── tests
```
