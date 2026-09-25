# Contributing

Thank you for helping. Security is the first priority of this project, so a few
rules apply to every change.

1. **Discuss first** for anything non-trivial: open an issue that describes the
   problem and the approach. Report security issues privately (see
   [SECURITY.md](SECURITY.md)), never in public issues.
2. **Set up** with `uv sync --group dev --group localdb` and install the hooks with
   `uvx pre-commit install`.
3. **Keep the architecture**: domain code stays framework-free, and every service
   method checks permissions and tenant scope. See
   [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
4. **Tests are required**: unit tests for logic; integration tests for anything that
   touches the database, RLS or HTTP; a security test for every new endpoint (401,
   403, cross-tenant 404, mass assignment).
5. **Run `make check`** before pushing. CI runs the same gates plus Semgrep,
   Gitleaks, CodeQL, Trivy and image builds.
6. **Commits** are small and focused, with an imperative subject line. Describe
   security-relevant changes explicitly in the pull request.
7. **Dependencies** are added with `uv add` so `uv.lock` stays hash-pinned; justify
   each new dependency in the pull request.

By contributing you agree that your contributions are licensed under the MIT license.
