import sb.parse_utils # for sb.parse_utils.init(...)
import io, tarfile, re    # if the output parameter is used

VERSION: str = "2025/10/6"
"""identify the version of the parser"""

FINDINGS: set[str]  = {
    "access-control",
}

def create_finding(section: str, func: str = None, level="warning", severity="high", message=None, exploit=None, address=None):
    """Helper per creare un finding JSON-serializzabile usando FINDINGS."""
    return {
        "name": "access-control",  # sempre dal set FINDINGS
        "function": func if func else None,
        "level": level,
        "severity": severity,
        "message": message if message else f"{section} in function {func}".strip(),
    }

def parse(exit_code, log, output):
    findings = []
    infos = set()
    errors, fails = sb.parse_utils.errors_fails(exit_code, log)

    check_re = re.compile(r"Checking contract for \x1b\[4m(.+?)\x1b\[0m")
    violated_re = re.compile(r"Violated access control check in function\s*(.*)", re.IGNORECASE)
    missing_re = re.compile(r"Missing access control check in function\s*(.*)", re.IGNORECASE)
   
    current_section = None
    skip_until_attacker = False
    bytecode_line = None  # per memorizzare la riga di bytecode da aggiungere al messaggio

    for line in log:
        text = line.strip()
        if not text:
            continue

        mcheck = check_re.search(text)
        if mcheck:
            current_section = mcheck.group(1).strip()
            skip_until_attacker = False
            bytecode_line = None
            continue

        if current_section is None:
            continue

        # CASO 1: Violated-AC-Check
        if current_section == "Violated-AC-Check":
            if skip_until_attacker:
                if text.startswith("+--Attacker"):
                    skip_until_attacker = False  # fine dello skip
                continue  # ignora tutte le righe finché non trovi il marker

            mv = violated_re.match(text)
            if mv:
                func = mv.group(1).strip()
                # prendi la prossima riga se è bytecode
                bytecode_line = next((l.strip() for l in log[log.index(line)+1:] if l.strip() and not l.strip().startswith("+--Attacker")), None)
                msg = f"Violated access control check in function {func}"
                if bytecode_line:
                    msg += f" | bytecode: {bytecode_line}"
                finding = create_finding(
                    section=current_section,
                    func=func,
                    level="high",
                    severity="high",
                    message=msg.strip()
                )
                findings.append(finding)
                skip_until_attacker = True  # ignora tutto il resto fino a "+--Attacker"
                continue

            # se la riga è solo bytecode senza pattern standard
            elif text and text != "------------------":
                finding = create_finding(
                    section=current_section,
                    func=None,
                    level="high",
                    severity="high",
                    message=f"Violated access control check | bytecode: {text}".strip()
                )
                findings.append(finding)
                continue


        # CASO 2: Missing-AC-Check
        elif current_section == "Missing-AC-Check":
            mm = missing_re.match(text)
            if mm:
                func = mm.group(1).strip()
                finding = create_finding(
                    section=current_section,
                    func=func,
                    level="high",
                    severity="high",
                    message=f"Missing access control check in function {func}".strip()
                )
                findings.append(finding)
            
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

