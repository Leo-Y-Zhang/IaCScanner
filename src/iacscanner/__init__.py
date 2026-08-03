"""IaCScanner: a defensive, local, read-only IaC misconfiguration scanner.

IaCScanner performs static analysis of Terraform, YAML, and JSON files on
the local filesystem only. It makes zero network calls, ships zero cloud
SDKs, and never needs credentials. It is an educational and defensive
tool: it reads files and prints findings, nothing more.
"""

__version__ = "1.2.0"
