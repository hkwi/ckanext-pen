# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/hkwi/ckanext-pen/compare/v0.1.0...HEAD)

* Test across CKAN 2.10, 2.11, 2.12 via a GitHub Actions matrix
  (Python follows the matching `ckan/ckan-dev` image per version).
* README: declare the supported CKAN range as `2.10 - 2.12`.

## [v0.1.0](https://github.com/hkwi/ckanext-pen/compare/v0.0.1...v0.1.0) - 2026-10-22

* Adopt PEP 621 metadata in `pyproject.toml`; drop `version` and
  `install_requires` from `setup.cfg` ([#16](https://github.com/hkwi/ckanext-pen/pull/16))
* Publish to PyPI on `v**` tag push via GitHub Actions + Trusted Publisher
  (`id-token: write`, no token secret required) ([#16](https://github.com/hkwi/ckanext-pen/pull/16))
* Add this `CHANGELOG.md` and rename the release flow accordingly ([#16](https://github.com/hkwi/ckanext-pen/pull/16))
* Bump Authlib 1.7.0 -> 1.8.0 -> 1.9.1 in `requirements.txt` and `setup.cfg`
  ([#14](https://github.com/hkwi/ckanext-pen/pull/14))
* README: correct the test image versions to `CKAN 2.11.6` / `Authlib 1.9.1`
  and fix the `docker compose run --rm ckan-test` command
  ([#15](https://github.com/hkwi/ckanext-pen/pull/15))
