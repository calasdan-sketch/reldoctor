# Publish checklist for Dan (nothing here has been run for you)

**Version to release: 0.3.0.** PyPI currently has only 0.1.0 (checked read-only on 2026-11-07 with `pip index versions reldoctor`).
The repo's version is already 0.3.0 everywhere, so do not bump it. It is not a drop-in upgrade for 0.1.0 users:
many more checks can now fail a release that used to pass. That is why it is a minor bump (0.1 -> 0.3), not a patch.
(0.2.0 was never published; the changelog entry for it is just history.)

## Before you publish: look at these first

1. Open `docs/ROUND4.md` and read "Decisions for Dan" at the bottom.
2. Check that the author name `Calas Automations Inc.` and the copyright line in `LICENSE` are what you want on a
   public package. Both were changed this round from your GitHub user name. Changing the copyright holder is a legal choice, so confirm it.
3. Push the branch and let GitHub Actions run. The new CI has a Windows job that nobody has seen pass yet. If it fails, tell Claude.
4. Merge to `main`, because the links in the package page point at `main`.

## Commands (run from the repo folder, in a clean virtual environment)

```bash
python -m venv /tmp/release-env && . /tmp/release-env/bin/activate
pip install build twine
rm -rf dist/ && python -m build
twine check dist/*
python -m pip install dist/*.whl          # into a throwaway environment, then:
reldoctor --version                        # must say 0.3.0
reldoctor dist/ --strict                   # reldoctor audits itself; must say PASS
```

Then upload (this is the one step that costs you your reputation if wrong, and it cannot be undone):

```bash
twine upload --repository testpypi dist/*      # optional dress rehearsal; needs a TestPyPI account
twine upload dist/*                            # the real one; needs a PyPI API token
git tag v0.3.0 && git push origin v0.3.0       # only after the upload worked
```

PyPI never lets you re-upload the same file name, so if something is wrong after upload you must release 0.3.1.

## After it is live

```bash
python -m venv /tmp/check && /tmp/check/bin/pip install reldoctor
/tmp/check/bin/reldoctor --version
```

It should print 0.3.0. If it prints 0.1.0, PyPI has not caught up yet; wait a few minutes.
