# Contributing

## Branches

- `main` is what has been released. Every commit on it is a tagged release or
  the merge that becomes one, and it is never pushed to directly.
- `development` collects the work for the next release. CI runs on every push
  to it.
- Work happens on a short-lived branch from `development`, named for what it
  does: `feature/audit-iterator`, `fix/retry-after`, `docs/examples`. Open a
  pull request into `development`, and delete the branch once it is merged.
  Dependabot's pull requests target `development` too.
- A release is a pull request from `development` into `main`. Once it is
  merged, tag the merge commit on `main` (see [Releasing](#releasing)), then
  merge `main` back into `development` if the two have diverged.
- An urgent fix to a release branches from `main` as `hotfix/...`, merges
  into `main` and is tagged as a patch release, and is then merged into
  `development`.

Keep commits focused and their messages in the imperative ("Add
ListAuditEvents limit check"). Rebase a branch onto `development` rather
than merging `development` into it.

## Tests

```sh
make vet test   # go vet, gofmt check, unit tests
make race       # unit tests with the race detector (needs cgo)
make cover      # coverage summary
make fuzz       # each fuzz target for 30s (FUZZTIME=2m for longer)
RYPT_TOKEN=... RYPT_KEY_ID=... make integration   # live API, about 10 operations
```

There are three kinds of test:

- **Unit tests** run every method against an in-process fake of the API
  built with `net/http/httptest`. They check the request each method sends,
  the result it decodes, its retry policy, and the handling of errors,
  malformed responses, redirects and hostile server text. They need no
  network and run in CI.
- **Contract tests** (`spec_test.go`) hold the client to the API's OpenAPI
  description in [testdata/openapi.json](testdata/openapi.json): every
  operation has a method that sends the right method and path, every schema
  has a type with exactly its fields, and every enum value has a constant.
  They run in CI.
- **Integration tests** (`integration_test.go`, build tag `integration`) run
  against the live API with your own token and key. They skip when
  `RYPT_TOKEN` or `RYPT_KEY_ID` is unset, never print the token, and do not
  run in CI.

### Updating the API description

When the API changes, replace `testdata/openapi.json` with its new OpenAPI
description, as JSON. The service's repository keeps it as YAML; convert it
without turning its timestamps into another format, for example:

```sh
python3 -c 'import json,sys,yaml
class L(yaml.SafeLoader): pass
L.yaml_implicit_resolvers = {k: [r for r in v if r[0] != "tag:yaml.org,2002:timestamp"] for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()}
json.dump(yaml.load(open(sys.argv[1]), Loader=L), sys.stdout, indent=2, ensure_ascii=False)' openapi.yaml > testdata/openapi.json
```

Then run `go test -run Spec`: its failures list what the client is missing.
Update the version named at the end of [doc.go](doc.go).

## Releasing

Versions follow [semantic versioning](https://semver.org): a patch release
fixes bugs, a minor release adds to the API, and a major release changes or
removes part of it. Before v1.0.0 a minor release may also change the API.
From v2 on, the module path must end in `/v2`.

1. On `development`, move the entries under "Unreleased" in
   [CHANGELOG.md](CHANGELOG.md) to a new version heading.
2. Merge `development` into `main` with a pull request, once CI passes.
3. Tag the merge commit and push the tag:

   ```sh
   git switch main && git pull
   git tag -a v0.2.0 -m v0.2.0
   git push origin v0.2.0
   ```

Pushing a `v*` tag runs [.github/workflows/release.yml](.github/workflows/release.yml),
which tests the tagged commit, publishes a GitHub release with notes
generated from the pull requests since the previous tag, and asks the Go
module proxy for the new version so that pkg.go.dev lists it. A tag with a
pre-release suffix, such as `v0.2.0-rc.1`, is published as a pre-release.

Never move or delete a tag once it is pushed: the Go module proxy and
checksum database keep the first content they saw for a version for good.
To undo a release, publish a new one, and list the bad version in a
`retract` directive in go.mod.
