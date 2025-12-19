import io
import tarfile
from typing import Optional

import sb.parse_utils

import csv

VERSION: str = "2025/12/10"

FINDINGS: {
    "tx-origin",
    "re-entrancy"
}

def parse(
    exit_code: Optional[int], log: list[str], output: bytes
) -> tuple[list[dict[str, object]], set[str], set[str], set[str]]:

    findings: list[dict[str, object]] = []
    infos: set[str] = set()
    errors, fails = sb.parse_utils.errors_fails(exit_code, log)

    tx_origin_file_found = False
    re_entrancy_file_found = False

    try:
        with io.BytesIO(output) as o, tarfile.open(fileobj=o) as tar:
            for f in tar.getmembers():
                if f.name.endswith("tx-origin.csv"):
                    tx_origin_tar = io.TextIOWrapper(tar.extractfile(f), encoding='utf-8')
                    tx_origin_csv = csv.reader(tx_origin_tar)
                    tx_origin_list = list(tx_origin_csv)[1:]
                    tx_origin_file_found = True
                if f.name.endswith("re-entrancy.csv"):
                    re_entrancy_tar = io.TextIOWrapper(tar.extractfile(f), encoding='utf-8')
                    re_entrancy_csv = csv.reader(re_entrancy_tar)
                    re_entrancy_list = list(re_entrancy_csv)[1:]
                    re_entrancy_file_found = True
    except Exception as e:
        fails.add(f"error parsing results: {e}")

    if tx_origin_file_found and re_entrancy_file_found:
        for row in tx_origin_list:
            issue = {}
            issue['name'] = "tx-origin"
            issue['address'] = int(row[0])
            issue['message'] = row[2]
            findings.append(issue)
        
        for row in re_entrancy_list:
            issue = {}
            issue['name'] = "re-entrancy"
            issue['address'] = int(row[0])
            issue['message'] = row[2]
            findings.append(issue)

    return findings, infos, errors, fails
