import io
import tarfile, os
from typing import Optional

import sb.parse_utils

import csv

VERSION: str = "2025/12/10"

FINDINGS: set[str]  = {
    "tx-origin",
    "re-entrancy"
}

def parse(
    exit_code: Optional[int], log: list[str], output: bytes
) -> tuple[list[dict[str, object]], set[str], set[str], set[str]]:

    findings, infos = [], set()
    errors, fails = sb.parse_utils.errors_fails(exit_code, log)

    tx_origin_rows = []
    reentrancy_rows = []

    has_tx_origin = False
    has_reentrancy = False

    if output is None or len(output) == 0:
        fails.add("error parsing results: no output generated")
        return findings, infos, errors, fails
    
    try:
        with io.BytesIO(output) as o, tarfile.open(fileobj=o) as tar:
            for member in tar.getmembers():
                if not member.name.startswith("out/"):
                    continue

                name = member.name.split("/")[-1]
                if "tx-origin.csv" in name:
                    f = tar.extractfile(member)
                    if f:
                        reader = csv.DictReader(io.TextIOWrapper(f, encoding="utf-8", errors="replace"))
                        tx_origin_rows = list(reader)
                        if len(tx_origin_rows) > 0:
                            has_tx_origin = True

                elif "re-entrancy.csv" in name:
                    f = tar.extractfile(member)
                    if f:
                        reader = csv.DictReader(io.TextIOWrapper(f, encoding="utf-8", errors="replace"))
                        reentrancy_rows = list(reader)
                        if len(reentrancy_rows) > 0:
                            has_reentrancy = True

    except Exception as e:
        fails.add(f"error parsing results: {e}")

    if has_tx_origin:
        tx_findings = [t['detection'] for t in tx_origin_rows]  
        tx_findings = list(set(tx_findings))

        issue = {}
        issue['name'] = "tx-origin"
        issue['message'] = tx_findings
        findings.append(issue)

    if has_reentrancy:
        reentrancy_findings = [r['detection'] for r in reentrancy_rows]
        reentrancy_findings = list(set(reentrancy_findings))

        issue = {}
        issue['name'] = "re-entrancy"
        issue['message'] = reentrancy_findings
        findings.append(issue)
            

    return findings, infos, errors, fails
