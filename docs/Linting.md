# Linting

The project uses [flake8](https://flake8.pycqa.org/) for PEP 8 style
enforcement.  Configuration lives in `.flake8` at the repository root.

## Current configuration

```ini
# .flake8
[flake8]
max-line-length = 98
```

The only project-specific override is raising the maximum line length from
the PEP 8 default of 79 to **98 characters**.

## Install flake8

flake8 is not listed as a runtime dependency; install it separately or add it
to your virtual environment:

```bash
pip install flake8
```

## Run flake8

```bash
# check the whole project
flake8 .

# check only the application module
flake8 app.py

# check the test suite
flake8 tests/
```

A clean run produces no output and exits with code `0`.

## Inline suppressions

A small number of long lines that cannot be broken without harming
readability carry a `# noqa: E501` comment:

```python
files=[("attachment", (os.path.basename(file_path), f, "application/octet-stream"))],  # noqa: E501
```

## CI integration

There is no automated CI pipeline in this repository at present.  To
enforce style checks locally before pushing, add flake8 to a pre-commit
hook:

```bash
pip install pre-commit
```

```yaml
# .pre-commit-config.yaml (create at the repository root)
repos:
  - repo: https://github.com/PyCQA/flake8
    rev: 7.2.0
    hooks:
      - id: flake8
```

```bash
pre-commit install   # installs the hook into .git/hooks/pre-commit
pre-commit run --all-files  # run manually against all files
```
