import sb.parse_utils # for sb.parse_utils.init(...)
import io, tarfile, json    # if the output parameter is used

VERSION: str = "2025/07/10"

FINDINGS: set[str]  = {
    "Reentrancy",
}


def parse(exit_code, log, output):
    findings, infos = [], set()
    errors, fails = sb.parse_utils.errors_fails(exit_code, log)
    # Parses the output for common Python/Java/shell exceptions (returned in 'fails')

    for line in log:
        # Puoi fare ulteriori analisi su stdout/stderr se vuoi
        pass

    try:
        with io.BytesIO(output) as o, tarfile.open(fileobj=o) as tar:
            # Provo ad estrarre "output.json"
            member = tar.getmember("output.json")
            contents = tar.extractfile(member).read()
            # Decodifico JSON
            results = json.loads(contents)

            for item in results:
                status = item.get("status")
                query_id = item.get("queryId", "unknown_query")
                exec_time = item.get("executionTime", None)

                # Se status è SATISFIABLE segnalo vulnerabilità di reentrancy
                if status == "SATISFIABLE":
                    finding = {
                        "name": "reentrancy",
                        "message": f"Reentrancy detected in query {query_id}",
                        "severity": "high",
                        "level": "error",
                        # puoi aggiungere altri campi se vuoi
                    }
                    findings.append(finding)

                # Se status è UNKNOWN o UNSATISFIABLE non faccio nulla (nessun finding)
                elif status in ("UNKNOWN", "UNSATISFIABLE"):
                    # eventualmente potresti aggiungere info o ignorare
                    infos.add(f"Query {query_id} returned status {status}")

                else:
                    # stato non riconosciuto, potrebbe essere interessante loggare
                    infos.add(f"Query {query_id} returned unexpected status {status}")

    except Exception as e:
        fails.add(f"error parsing results: {e}")

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

