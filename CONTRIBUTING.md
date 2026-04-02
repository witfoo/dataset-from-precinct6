# Contributing

Thank you for your interest in contributing to the Precinct6 Dataset Generator.

## Development Setup

```bash
git clone https://github.com/witfoo/dataset-from-precinct6.git
cd dataset-from-precinct6
pip install -e ".[dev,all]"
python -m spacy download en_core_web_lg
```

## Running Tests

```bash
pytest
```

## Code Style

We use [ruff](https://github.com/astral-sh/ruff) for linting:

```bash
ruff check src/
ruff format src/
```

## Security

**Never commit secrets.** Before any commit, run:

```bash
grep -rn 'password\|secret\|api.key\|token' src/ --include="*.py" | grep -v 'os.getenv\|environ'
```

If you discover a security vulnerability, please report it privately to security@witfoo.com.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
