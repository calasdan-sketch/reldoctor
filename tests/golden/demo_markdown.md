### reldoctor: FAIL (4 error(s), 2 warning(s))

| | check | file | what |
|---|---|---|---|
| x | `invalid_classifier` | acme\_widgets-1.0.0-cp312-cp312-manylinux2014\_x86\_64.whl | classifier 'Topic :: Software Development :: Widgets' is not a valid trove classifier \(checked against trove-classifiers 2026.9.21.13\); PyPI rejects the upload. Fix the spelling or remove it. |
| ! | `readme_relative_links` | acme\_widgets-1.0.0-cp312-cp312-manylinux2014\_x86\_64.whl | long description links to 1 relative path\(s\) \('docs/logo.png'\); PyPI does not resolve them, so they render broken. Use absolute https:// URLs |
| x | `secret_in_file` | acme\_widgets-1.0.0-cp312-cp312-manylinux2014\_x86\_64.whl | 'acme\_widgets/settings.py' contains what looks like a Stripe live key \(value not shown\); it would be public on PyPI. If this is a deliberate test fixture, exempt it with --allow-path |
| ! | `local_path_leak` | acme\_widgets-1.0.0-cp312-cp312-manylinux2014\_x86\_64.whl | 1 file\(s\) contain a personal home-directory path for user\(s\) j\*\*\* \(e.g. 'acme\_widgets/\_speed.cpython-312-x86\_64-linux-gnu.so'\); it exposes a username and machine layout. Build in a clean container or strip paths |
| x | `binary_arch_mismatch` | acme\_widgets-1.0.0-cp312-cp312-manylinux2014\_x86\_64.whl | 'acme\_widgets/\_speed.cpython-312-x86\_64-linux-gnu.so' is built for arm64 but the wheel tag 'manylinux2014\_x86\_64' promises x86\_64; it will fail to import there |
| x | `manylinux_glibc_too_new` | acme\_widgets-1.0.0-cp312-cp312-manylinux2014\_x86\_64.whl | 'acme\_widgets/\_speed.cpython-312-x86\_64-linux-gnu.so' references GLIBC\_2.34 but the tag promises glibc 2.17; 'auditwheel repair' would relabel it manylinux\_2\_34 |
| i | `sdist_version` | acme\_widgets-1.0.0.tar.gz | PKG-INFO version 1.0.0 |
| i | `diff_new_files` |  | acme\_widgets-1.0.0-cp312-cp312-manylinux2014\_x86\_64.whl: 1 file\(s\) added \(e.g. 'acme\_widgets/settings.py'\) |
