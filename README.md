# vendor-trust-audit

Find and rank the AWS IAM roles that **third-party vendors can assume**: which vendor, whether the role is still
used, whether `sts:ExternalId` is the only thing standing between an attacker and your account, and what secrets
the role can read.

In October 2026 an attacker took over IAM users in Qubole's AWS account and used `sts:AssumeRole` against the
integration roles customers had created to trust that account. Every call carried the right External ID, many of the
roles were dormant, and the attacker read Secrets Manager, SSM Parameter Store and Lambda environment variables
([Wiz](https://www.wiz.io/blog/qubole-cross-account-access-abused-in-the-wild),
[BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-trusted-aws-access-to-breach-multiple-cloud-environments/)).
This tool answers the question every AWS customer had to answer afterwards, for every vendor at once.

```
pip install "vendor-trust-audit[live] @ git+https://github.com/garag0l/vendor-trust-audit@v0.1.0"
```

No runtime dependencies for offline mode; `boto3` only for `--live`.

## Usage

```bash
# offline: one export per account (works in CI, on IaC exports, and on evidence from an assessment)
aws iam get-account-authorization-details --output json > acct.json
vendor-trust-audit --gaad acct.json --internal-accounts org-accounts.txt --org-id o-abc123

# live, read-only (iam:GetAccountAuthorizationDetails); repeat --profile for several accounts
vendor-trust-audit --live --profile prod --profile data

# SARIF for code scanning, JSON for pipelines
vendor-trust-audit --gaad acct.json -f sarif -o vta.sarif

# IR scoping: who assumed the flagged roles since a date, and what they read
vendor-trust-audit --gaad acct.json --cloudtrail-query 2026-09-01
```

| Flag | Meaning |
| --- | --- |
| `--internal-accounts IDS\|FILE` | Accounts that are yours (e.g. every Org account). Trust from them is not vendor trust. |
| `--org-id o-...` | Trust narrowed by `aws:PrincipalOrgID` equal to this id is internal. |
| `--vendor-map FILE` | `{"123456789012": "Vendor"}` for partners missing from the built-in list. |
| `--dormant-days N` | Unused for N days = dormant (default 90). `--now DATE` makes reports reproducible. |
| `--fail-on SEV` | Exit 1 at `critical`/`high`/`medium`/`low` or above (default `high`); `none` always exits 0. |

Sample output (from the test fixture, which reproduces the Qubole trust shape):

```
Vendors with access
  anyone (Principal "*"): 1 role(s)
    CRITICAL open-trust-test                          last used 2026-11-24  reach: -
  qubole (805246085872): 2 role(s)
    CRITICAL qubole-integration                       last used 2025-03-02  reach: secretsmanager,ssm-parameters,lambda-env,s3-read
    HIGH     qubole-integration-sourceip              last used 2026-11-20  reach: secretsmanager,ssm-parameters,lambda-env,s3-read
  UNKNOWN (999988887777): 2 role(s)
    HIGH     partner-reporting                        last used 2026-11-01  reach: -
  ...
[HIGH] VTA-004 arn:aws:iam::111122223333:role/qubole-integration
       sts:ExternalId is the only thing restricting who can assume the role
       ...
       fix: Add aws:SourceIp (vendor egress ranges) or aws:PrincipalArn (vendor role) to the trust policy. ...
```

## Checks

| ID | Severity | What it finds |
| --- | --- | --- |
| VTA-001 | info / medium | Role assumable by an external account. Named via a pinned snapshot of [known_aws_accounts](https://github.com/fwdcloudsec/known_aws_accounts); an **unknown** account is medium. Deleted principals (shown as `AROA…` ids) are reported too. |
| VTA-002 | medium / high | **Dormant trust**: `RoleLastUsed` empty or older than `--dormant-days`. High when the role can read secrets. |
| VTA-003 | medium | Trust names the vendor **account root** (or bare account id) rather than a specific vendor role, so any principal in the vendor account with `sts:AssumeRole` qualifies. |
| VTA-004 | low – high | **ExternalId-only** trust (no `aws:SourceIp`, `aws:SourceVpce`, `aws:SourceVpc`, `aws:PrincipalOrgID`, `aws:PrincipalArn`, `aws:PrincipalTag/*`, `aws:SourceIdentity`); **missing** ExternalId; the same ExternalId **reused** across roles or vendors. `…IfExists` and negated operators do not count as narrowing. ExternalId values are never printed. |
| VTA-005 | medium – critical | **Secret reach**: after permission boundaries and explicit denies, the role can call `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `lambda:GetFunction[Configuration]`, `kms:Decrypt`, or broad `s3:GetObject` / `iam:PassRole` / `sts:AssumeRole`. Critical when combined with dormant or un-narrowed trust. |
| VTA-006 | high / critical | `Principal: "*"` or `{"AWS": "*"}`: critical without conditions, high when only conditions restrict it. |

Not reported: service principals (`ec2.amazonaws.com` …), federated principals (SAML/OIDC), your own account,
`--internal-accounts`, and `aws:PrincipalOrgID == --org-id`.

## GitHub Action

```yaml
- uses: garag0l/vendor-trust-audit@v0.1.0
  with:
    gaad: exports/prod.json exports/data.json
    format: sarif
    output: vta.sarif
    fail-on: high
    args: --internal-accounts exports/org-accounts.txt
- uses: github/codeql-action/upload-sarif@v4
  with: { sarif_file: vta.sarif }
```

## How it works and its limits

- The trust parser handles every `Principal` form (`"*"`, account id, `:root`, role/user/assumed-role ARNs, unique ids),
  `Action`/`NotAction`, and the condition operators that do or do not bind the caller.
- The permission evaluator handles Allow/Deny, `Action`/`NotAction`, `Resource`/`NotResource`, wildcards and permission
  boundaries. Conditions on Allow statements mark a result as *conditional*; conditional Denies are not assumed to
  apply. It intersects wildcard resources exactly for the common shapes (`*`, service-wide, prefix/`*`, exact) and
  can over-report for unusual overlapping patterns; it does not under-report on those shapes (property-tested).
- **Not evaluated:** SCPs/RCPs, resource policies (secret, bucket and KMS key policies) and session policies. VTA-005
  is therefore an upper bound on reach. Pair it with [`secret-reach`](https://github.com/garag0l/secret-reach) to get the
  exact list of resources to rotate.
- `RoleLastUsed` only covers the IAM tracking window (about 400 days); "never" means not used within it.
- Vendor names come from a community list (pinned commit in `data/known_aws_accounts.json`); regenerate with
  `python scripts/update_vendors.py`.

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest -q
python tests/build_fixture.py   # regenerates the fixture; CI checks it is reproducible
```

Tests cover each check, every trust principal form and condition-operator edge case, the evaluator (including a
randomized no-false-negative property test), JSON/SARIF/CloudTrail output, a moto-backed live run, and a 2,000-role
export in under 5 seconds.

## Authorized use only

Run this only against AWS accounts you own or are explicitly authorized to assess. It is read-only and makes no
changes, but IAM exports describe your security posture: store reports and exports as sensitive data.

## License

MIT. The bundled vendor list is derived from [fwdcloudsec/known_aws_accounts](https://github.com/fwdcloudsec/known_aws_accounts) (Apache-2.0).
