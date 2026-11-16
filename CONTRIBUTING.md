# Contributing

Thanks for looking. Small, focused changes are the easiest to review.

1. Fork, create a branch, change one thing.
2. Run `make test`. If behaviour changed, run `make sample` and commit the regenerated files, because CI fails when `examples`, `docs` or `site` are out of date.
3. Add or update a test next to the change. A false positive or false negative report with a minimal input is a valuable contribution on its own.
4. Open a pull request and say what the change fixes.

Security issues go through the private process in `SECURITY.md`, not through public issues.
