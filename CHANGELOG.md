# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-25

### Added
- Inventory of every IAM role whose trust policy admits an AWS principal outside the account (and outside
  `--internal-accounts` / `--org-id`), with vendor names from a pinned snapshot of
  [fwdcloudsec/known_aws_accounts](https://github.com/fwdcloudsec/known_aws_accounts) (Apache-2.0) plus `--vendor-map`.
- Checks **VTA-001** vendor identity / unknown account, **VTA-002** dormant trust (`RoleLastUsed`), **VTA-003** vendor
  account root principal, **VTA-004** ExternalId-only / missing / reused ExternalId, **VTA-005** secret reach
  (Secrets Manager, SSM parameters, Lambda env, KMS decrypt, wildcard S3 read, wildcard PassRole / AssumeRole) after
  permission boundaries and explicit denies, **VTA-006** wildcard principal.
- Offline (`--gaad`, repeatable for several accounts) and live (`--live`, `--profile` repeatable, read-only) modes.
- Text (grouped by vendor), JSON and SARIF output; `--cloudtrail-query SINCE` prints CloudTrail Lake and Athena
  queries that scope `AssumeRole` calls into the flagged roles and what those sessions read.
- Composite GitHub Action (`action.yml`).
