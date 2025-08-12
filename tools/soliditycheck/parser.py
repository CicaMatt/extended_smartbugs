import sb.parse_utils # for sb.parse_utils.init(...)
import io, tarfile    # if the output parameter is used

VERSION: str = "2025/07/9"

FINDINGS: set[str]  = {
    "Reentrancy",
}


def parse(exit_code, log, output):
    """
    Analizza il risultato del tool.
    """
    findings, infos = [], set()
    errors, fails = sb.parse_utils.errors_fails(exit_code, log)

    reentrancy_found = False
    line_number = None
    function_name = None

    for line in log:
        if "No reentrant" in line:
            infos.add("No reentrancy detected.")
        elif "-----Insert line number-----" in line:
            reentrancy_found = True
        elif line.startswith("line "):
            try:
                line_number = int(line.split(" ", 1)[1].strip())
            except Exception:
                line_number = None
        elif "function name:" in line:
            function_name = line.split(":", 1)[1].strip()
        elif "Parameter types:" in line and "Name of parameter:" in line:
            # Esempio riga: Parameter types: uint  Name of parameter: _amount
            try:
                type_part = line.split("Parameter types:")[1].split("Name of parameter:")[0].strip()
                name_part = line.split("Name of parameter:")[1].strip()
                infos.add(f"Parameter: {name_part} (type: {type_part})")
            except Exception:
                infos.add("Could not parse parameter information.")

    if reentrancy_found:
        findings.append({
            "name": "Reentrancy",
            "function": function_name if function_name else None,
            "line": line_number,
            "message": "Reentrancy vulnerability detected.",
            "severity": "high",
        })

    return findings, infos, errors, fails


    """
    findings is a list of issues. Each issue is a dict with the following fields.
    name: str
        mandatory. Identifies the type of issue
    filename: str
        optional. Path of file processed. As this is the path within
        the docker image, it will be replaced by the external filename,
        after parsing.
    contract: str
        optional. Name of contract within the file (for source code)
    function: str
        optional. Name/header/signature of function containing the issue
    line: int
        optional. Line number of issue in source code, starting with 1
    column: int
        optional. Column of issue in source code, starting with 1
    line_end: int
        optional. Last line of the source code, where issue occurs.
    column_end: int
        optional. Last column of the source code, where issue occurs.
    address: int
        optional. Address of instruction in the bytecode, where issue occurs, starting with 0
    address_end: int
        optional. Address of last instruction in the bytecode, where issue occurs, starting with 0
    exploit: Any
        optional. Information on a potential exploit, e.g. a list of transactions
    level: str
        optional. type of issue, e.g. recommendation, warning, error
    severity: str
        optional. Severity of issue, e.g. low, medium, high
    message: str
        optional. Description of the issue

    If missing, the fields severity, classification, method, descr_short,
    descr_long will be taken from the file findings.yaml in the tools
    directory (if it exists), with "name" serving as the key.
    """

