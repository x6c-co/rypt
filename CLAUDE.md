<!-- repo-setup:begin (managed by /repo-setup; edit outside this block) -->
## Repo facts

- Repo type: library
- Languages: go
- Check command: `make check`
- Versioning: SemVer tags `vMAJOR.MINOR.PATCH`
- Default branch: `main`
- Claude may commit: yes
- taskd project: rypt
<!-- repo-setup:end -->

## Branching

This repo does not use plain GitHub Flow. It overrides the global branching
rules as follows; [CONTRIBUTING.md](CONTRIBUTING.md) has the details.

- Feature branches start from `development`, not `main`.
- Pull requests target `development`: run `gh pr create --base development`.
- A release is a pull request from `development` into `main`, then a `v*`
  tag on the merge commit. Hotfixes branch from `main` as `hotfix/...`.
