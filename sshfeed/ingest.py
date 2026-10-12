"""Parse sshd auth.log lines and Cowrie JSON events into one event schema:
{ts, src_ip, user, outcome: fail|invalid_user|success|preauth_close|break_in_warn, source}"""
import json, re

PATTERNS = [
    (re.compile(r"Failed password for invalid user (\S*) from ([\d.a-fA-F:]+)"), "invalid_user"),
    (re.compile(r"Failed password for (\S+) from ([\d.a-fA-F:]+)"), "fail"),
    (re.compile(r"Invalid user (\S*) from ([\d.a-fA-F:]+)"), "invalid_user_probe"),
    (re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from ([\d.a-fA-F:]+)"), "success"),
    (re.compile(r"reverse mapping checking getaddrinfo for \S+ \[([\d.]+)\] failed - POSSIBLE BREAK-IN"), "break_in_warn"),
    (re.compile(r"authentication failure;.*rhost=([\d.a-zA-Z\-]+)(?:\s+user=(\S+))?"), "pam_fail"),
]
TS = re.compile(r"^(\w{3}\s+\d+\s[\d:]{8})")


def parse_authlog(lines, source="authlog"):
    out = []
    for line in lines:
        m0 = TS.match(line)
        for rx, kind in PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            if kind == "break_in_warn":
                user, ip = None, m.group(1)
            elif kind == "pam_fail":
                ip, user = m.group(1), m.group(2)
                if not re.fullmatch(r"[\d.]+", ip):
                    break  # hostname rhost: no IP, skip (would need DNS)
            else:
                user, ip = m.group(1), m.group(2)
            out.append({"ts": m0.group(1) if m0 else None, "src_ip": ip, "user": user, "outcome": kind, "source": source})
            break
    return out


COWRIE = {"cowrie.login.failed": "fail", "cowrie.login.success": "success", "cowrie.command.input": "command"}


def parse_cowrie(lines):
    out = []
    for line in lines:
        e = json.loads(line)
        kind = COWRIE.get(e.get("eventid"))
        if kind:
            out.append({"ts": e.get("timestamp"), "src_ip": e["src_ip"], "user": e.get("username"), "outcome": kind,
                        "password": e.get("password"), "command": e.get("input"), "source": "cowrie"})
    return out
