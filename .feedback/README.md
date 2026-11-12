# Feedback task starting environment

Upstream: https://github.com/py-pdf/pypdf
Upstream commit: `3163b84cdbcf20615808ae4179238a657209fb7a`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_protocols.py tests/test_filters.py::test_flate_decode_encode tests/test_filters.py::test_ascii_hex_decode_method tests/test_filters.py::test_decompress_zlib_error
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `22 passed in 0.14s`
Whole-command wall time: 0.315 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
