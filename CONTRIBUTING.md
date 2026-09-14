Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.  
SPDX-License-Identifier: BSD-3-Clause

## Contributing to SBOM Check

Hi there!
We’re thrilled that you’d like to contribute to this project.
Your help is essential for keeping this project great and for making it better.

## Branching Strategy

In general, contributors should develop on branches based off of `main` and pull requests should be made against `main`.

## Development Environment Setup

### Initial Setup

```bash
# Install with development dependencies (default behavior)
uv sync

# Install production dependencies only (if needed)
uv sync --no-dev
```

### Available Tox Environments

- **Quality Assurance**: `ruff-format`, `ruff-check`, `ruff-fix`, `mypy`, `pylint`
- **Testing**: `py310`, `py311`, `py312`, `py313`, `test-unit`, `test-integration`, `test-parallel`
- **Utilities**: `clean`, `dev`

### Quick Development Workflow

```bash
# Format and fix code issues
uv run tox -e ruff-format,ruff-fix

# Run all quality checks
uv run tox -e ruff-check,mypy,pylint -p auto

# Run tests with coverage
uv run tox -e py310

# Run complete quality pipeline (format + lint + test all Python versions)
uv run tox

# Run quality pipeline in parallel (faster)
uv run tox -p auto

# Clean up generated files
uv run tox -e clean
```

### Project Structure

```
sbom-check/
├── src/
│   ├── sbom_check/          # Main SBOM-Check package
│   │   ├── cli.py          # SBOM-Check CLI
│   │   ├── engine.py       # Validation engine with profiles
│   │   ├── models.py       # SBOM-Check data models
│   │   └── config/         # Configuration system
│   └── spdx_validator/     # Integrated SPDX validator library
│       ├── cli.py          # SPDX-Validate CLI
│       ├── data/           # Bundled SPDX schema
│       │   └── spdx-2.3-spec.json
│       ├── engine.py       # Core SPDX validation engine
│       ├── models.py       # SPDX data models
│       └── validators.py   # JSON Schema & semantic validators
├── tests/                  # Test suite
│   ├── unit/sbom_check/    # SBOM-Check tests
│   └── unit/spdx_validator/ # SPDX-Validator tests
├── pyproject.toml          # Project configuration
└── Makefile               # Development workflow
```

## Submitting a pull request

1. Please read our [code of conduct](CODE-OF-CONDUCT.md) and [license](LICENSE).
1. [Fork](https://github.com/quic/sbom-check) and clone the repository.
 
    ```bash
    git clone https://github.com/<username>/sbom-check.git
    ```

1. Create a new branch based on `main`:

    ```bash
    git checkout -b <my-branch-name> main
    ```

1. Create an upstream `remote` to make it easier to keep your branches up-to-date:

    ```bash
    git remote add upstream https://github.com/quic/sbom-check.git
    ```

1. Make your changes, add tests, and make sure the tests, code quality, typing annotation, and style checks still pass. See the [Quick Development Workflow](#quick-development-workflow) section above for detailed commands.

1. Commit your changes using the [DCO](http://developercertificate.org/). You can attest to the DCO by commiting with the **-s** or **--signoff** options or manually adding the "Signed-off-by":

    ```bash
    git commit -s -m "Really useful commit message"`
    ```

1. After committing your changes on the topic branch, sync it with the upstream branch:

    ```bash
    git pull --rebase upstream main
    ```

1. Push to your fork.

    ```bash
    git push -u origin <my-branch-name>
    ```

    The `-u` is shorthand for `--set-upstream`. This will set up the tracking reference so subsequent runs of `git push` or `git pull` can omit the remote and branch.

1. [Submit a pull request](https://github.com/quic/sbom-check/pulls) from your branch to `main`.
1. Pat yourself on the back and wait for your pull request to be reviewed.

Here are a few things you can do that will increase the likelihood of your pull request to be accepted:

- Follow the existing [style](https://peps.python.org/pep-0008/) where possible.
- Write tests.
- Keep your change as focused as possible.
  If you want to make multiple independent changes, please consider submitting them as separate pull requests.
- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).
- It's a good idea to arrange a discussion with other developers to ensure there is consensus on large features, architecture changes, and other core code changes. PR reviews will go much faster when there are no surprises.
