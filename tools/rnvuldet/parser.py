import sb.parse_utils # for sb.parse_utils.init(...)
import io, tarfile , json   # if the output parameter is used

VERSION = "2025/10/7"

FINDINGS = {
    "Bad-Randomness"
}

def parse(exit_code, log, output):
    """
    Analyse the result of the tool run.
    """
    findings, infos = [], set()
    errors, fails = sb.parse_utils.errors_fails(exit_code, log)

    # 1️⃣ Analisi del log: se contiene un Traceback, è un fallimento
    for line in log:
        if "Traceback (most recent call last):" in line:
            fails.add("Python traceback detected")
            return findings, infos, errors, fails
        # elif "Error" in line or "Exception" in line:
        #     errors.add(line.strip())
        #     return findings, infos, errors, fails



    # A volte il JSON è stampato direttamente nel log
    joined_log = "\n".join(log)
    try:
        data = json.loads(joined_log)
        if data['is_reported']:
            findings.append({
                "name": "Bad-Randomness",
                "message": f"Steps={data['steps']}, Conditions={data['conditions']}, Call Values={data['call_values']}",
                "severity": "Medium"
            })
        else:
            infos.add("No issues found.")
    except json.JSONDecodeError:
        errors.add("Error parsing JSON directly from log output.")
        return findings, infos, errors, fails

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

