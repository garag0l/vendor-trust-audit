# vendor-trust-audit
Finds AWS IAM roles assumable by outside vendors and flags risky trust: dormant roles, root-principal trust, ExternalId-as-only-control, secret-readable roles (the Qubole cross-account breach pattern).
