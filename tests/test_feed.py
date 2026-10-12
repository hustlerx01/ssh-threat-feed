from pathlib import Path
import json
from sshfeed.ingest import parse_authlog, parse_cowrie
from sshfeed.feed import build, export, allowed

FX = Path(__file__).parent / "fixtures"
LINES = [
    "Dec 10 06:55:46 h sshd[1]: Invalid user webmaster from 198.51.100.9",
    "Dec 10 06:55:48 h sshd[1]: Failed password for invalid user webmaster from 198.51.100.9 port 38926 ssh2",
    "Dec 10 06:55:49 h sshd[1]: Failed password for root from 198.51.100.9 port 38927 ssh2",
    "Dec 10 07:00:00 h sshd[2]: Accepted password for deploy from 10.1.2.3 port 5000 ssh2",
    "Dec 10 07:01:00 h sshd[3]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.9  user=root",
]


def test_parse_authlog_outcomes():
    ev = parse_authlog(LINES)
    assert [e["outcome"] for e in ev] == ["invalid_user_probe", "invalid_user", "fail", "success", "pam_fail"]
    assert all(e["src_ip"] for e in ev)


def test_cowrie_success_after_bruteforce_alerts_and_commands_scored():
    ev = parse_cowrie(open(FX / "cowrie.json"))
    feed, alerts, clusters = build(ev, min_score=0)
    assert any(a["ip"] == "203.0.113.66" for a in alerts)
    top = {f["ip"]: f for f in feed}["203.0.113.66"]
    assert top["success"] == 1 and top["score"] >= 30


def test_playbook_cluster_groups_same_wordlist():
    _, _, clusters = build(parse_cowrie(open(FX / "cowrie.json")), min_score=0)
    assert ["198.51.100.31", "198.51.100.32"] in [sorted(c) for c in clusters]


def test_internal_success_not_in_feed():
    feed, alerts, _ = build(parse_authlog(LINES), min_score=0)
    assert "10.1.2.3" not in {f["ip"] for f in feed} and not alerts
    assert allowed("10.1.2.3") and not allowed("198.51.100.9")


def test_export_stix_valid(tmp_path):
    feed, alerts, cl = build(parse_cowrie(open(FX / "cowrie.json")), min_score=0)
    export(feed, alerts, cl, tmp_path)
    b = json.load(open(tmp_path / "feed.stix.json"))
    ind = [o for o in b["objects"] if o["type"] == "indicator"]
    assert len(ind) == len(feed) and ind[0]["pattern"].startswith("[ipv4-addr:value")
    assert (tmp_path / "blocklist.txt").read_text().count("\n") == len(feed) + 1
