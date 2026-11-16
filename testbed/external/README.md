# External testbeds

Crawlers' testbeds written by others, run locally in Docker, so that the
frontier is not tuned to fixtures of its own (docs/gd3-external-results.md).

- **Crawlground** (zaproxy/crawlground, commit `ba52303`, Apache-2.0): 59
  tests, scored by the server itself (`POST /set-tool`, `GET /results.json`).
  Image `jsh-ext-crawlground`: `docker build -t jsh-ext-crawlground .` in a
  checkout of the repository (its own Dockerfile).
- **security-crawl-maze** (google/security-crawl-maze, commit `2a0dd0a`,
  Apache-2.0): 91 answers in `crawlmaze-expected.json` (copied from
  `blueprints/utils/resources/expected-results.json`); 84 count, the 7
  framework apps do not build. Image `jsh-ext-crawlmaze`: the upstream image
  no longer builds, so `Dockerfile.crawlmaze` builds the Flask app alone,
  with the Flask 1.0 era pins; copy it into a checkout and
  `docker build -f Dockerfile.crawlmaze -t jsh-ext-crawlmaze .`.

`run.sh` runs jsharvest's frontier on both and scores it; it needs the two
images, and is not part of the per-commit gates (about 8 minutes).
