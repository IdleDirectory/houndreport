"""NIST SP 800-171 r2 control references and their CMMC Level 2 practice IDs."""

from __future__ import annotations

FAMILIES = {
    "3.1": "AC", "3.2": "AT", "3.3": "AU", "3.4": "CM", "3.5": "IA", "3.6": "IR", "3.7": "MA",
    "3.8": "MP", "3.9": "PS", "3.10": "PE", "3.11": "RA", "3.12": "CA", "3.13": "SC", "3.14": "SI",
}

TITLES = {
    "3.1.1": "Limit system access to authorized users, processes and devices",
    "3.1.2": "Limit system access to the transactions and functions users are permitted to execute",
    "3.1.5": "Employ least privilege, including for security functions and privileged accounts",
    "3.1.6": "Use non-privileged accounts when accessing nonsecurity functions",
    "3.1.7": "Prevent non-privileged users from executing privileged functions",
    "3.1.12": "Monitor and control remote access sessions",
    "3.4.1": "Establish and maintain baseline configurations and inventories",
    "3.4.2": "Establish and enforce security configuration settings",
    "3.4.6": "Employ the principle of least functionality",
    "3.5.2": "Authenticate the identities of users, processes or devices",
    "3.5.3": "Use multifactor authentication for privileged accounts",
    "3.5.6": "Disable identifiers after a defined period of inactivity",
    "3.5.7": "Enforce minimum password complexity",
    "3.5.10": "Store and transmit only cryptographically-protected passwords",
    "3.11.2": "Scan for vulnerabilities periodically",
    "3.11.3": "Remediate vulnerabilities in accordance with risk assessments",
    "3.13.10": "Establish and manage cryptographic keys",
    "3.14.1": "Identify, report and correct system flaws in a timely manner",
}


def cmmc_id(nist_id: str) -> str:
    family = FAMILIES.get(nist_id.rsplit(".", 1)[0], "XX")
    return f"{family}.L2-{nist_id}"


def control_refs(nist_ids: list[str]) -> list[dict[str, str]]:
    return [{"nist": i, "cmmc": cmmc_id(i), "title": TITLES.get(i, "")} for i in nist_ids]
