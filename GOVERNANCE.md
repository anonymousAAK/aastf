# AASTF Governance

## Maintainers

| Name | Role | GitHub |
|------|------|--------|
| Adarsh Keshri | Lead Maintainer | [@anonymousAAK](https://github.com/anonymousAAK) |

## Decision Process

AASTF uses **lazy consensus** for most decisions:

1. A proposal is made via GitHub Issue or Pull Request.
2. If no objections are raised within **72 hours**, the proposal is considered accepted.
3. **Breaking changes** (API removals, scenario schema changes, verdict renames) require:
   - A GitHub Issue labeled `breaking-change`
   - A minimum 72-hour review period
   - Explicit approval from the lead maintainer
4. Security-sensitive changes require review from the lead maintainer before merge.

## Release Process

1. **Version bump** -- Update version in `pyproject.toml`, `src/aastf/__init__.py`, and `CITATION.cff`.
2. **Changelog** -- Update `CHANGELOG.md` with all notable changes following Keep a Changelog format.
3. **Tag** -- Create a signed Git tag: `git tag -s v0.X.Y -m "Release v0.X.Y"`.
4. **CI pipeline** -- Push the tag. The `release.yml` workflow will:
   - Build sdist and wheel
   - Sign artifacts with Sigstore
   - Publish to PyPI via OIDC trusted publisher
   - Create a GitHub Release with signed artifacts and `.sigstore` bundles
5. **Verify** -- Confirm the package appears on [PyPI](https://pypi.org/project/aastf/) and the GitHub Release contains all expected assets.

## Security Policy

See [SECURITY.md](SECURITY.md) for vulnerability reporting, response timelines, and scope.

## Code of Conduct

All participants in the AASTF project are expected to follow the [Contributor Covenant Code of Conduct v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

In summary:
- Be respectful, inclusive, and constructive.
- Harassment, trolling, and personal attacks are not tolerated.
- Report violations to the lead maintainer via the email listed in SECURITY.md.

## Contributing

1. Fork the repo and create a feature branch.
2. Ensure `ruff check` and `pytest tests/unit/` pass.
3. Open a Pull Request against `master`.
4. All PRs require at least one review before merge.
