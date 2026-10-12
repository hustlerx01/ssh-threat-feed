"""Aggregate events per attacker IP, score, cluster by credential 'playbook'
(ShardLure-style), check successes against an allow-list (SSH-Log-Alert idea),
and export txt/csv/json/STIX 2.1."""
import csv, ipaddress, json
from collections import Counter, defaultdict

ALLOW_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def allowed(ip, extra=()):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in ALLOW_NETS + [ipaddress.ip_network(x) for x in extra])


def aggregate(events):
    agg = defaultdict(lambda: {"attempts": 0, "fails": 0, "invalid_user": 0, "success": 0, "break_in_warn": 0,
                               "users": Counter(), "commands": [], "first_seen": None, "last_seen": None, "sources": set()})
    for e in events:
        a = agg[e["src_ip"]]
        o = e["outcome"]
        if o in ("fail", "invalid_user", "pam_fail"):
            a["attempts"] += 1; a["fails"] += 1
        if o in ("invalid_user", "invalid_user_probe"):
            a["invalid_user"] += 1
        if o == "success":
            a["attempts"] += 1; a["success"] += 1
        if o == "break_in_warn":
            a["break_in_warn"] += 1
        if o == "command" and e.get("command"):
            a["commands"].append(e["command"])
        if e.get("user") and o != "command":
            a["users"][e["user"]] += 1
        a["first_seen"] = a["first_seen"] or e["ts"]; a["last_seen"] = e["ts"] or a["last_seen"]
        a["sources"].add(e["source"])
    return agg


def score(a):
    """0-100. Volume (log-ish), username diversity, invalid users, success after failure, post-auth commands."""
    s = min(a["fails"], 200) / 200 * 40
    s += min(len(a["users"]), 20) / 20 * 20
    s += 10 if a["invalid_user"] else 0
    s += 5 if a["break_in_warn"] else 0
    s += 30 if a["success"] and a["fails"] >= 5 else 0  # compromise is worse than volume
    s += 10 if a["commands"] else 0
    return round(min(s, 100))


def jaccard(x, y):
    return len(x & y) / len(x | y) if x | y else 0.0


def cluster(agg, thr=0.5, min_users=3):
    """Greedy single-link clustering of IPs by the set of usernames tried -> shared wordlist/playbook."""
    ips = [ip for ip, a in agg.items() if len(a["users"]) >= min_users]
    sets = {ip: set(agg[ip]["users"]) for ip in ips}
    clusters = []
    for ip in sorted(ips, key=lambda i: -len(sets[i])):
        for c in clusters:
            if any(jaccard(sets[ip], sets[o]) >= thr for o in c):
                c.append(ip); break
        else:
            clusters.append([ip])
    return [c for c in clusters if len(c) > 1]


def build(events, min_score=30, allow_extra=()):
    agg = aggregate(events)
    feed, alerts = [], []
    for ip, a in agg.items():
        if allowed(ip, allow_extra):
            if a["success"] and a["fails"] >= 5:
                alerts.append({"ip": ip, "why": "internal source brute-forced then succeeded (possible compromised host)"})
            continue
        if a["success"]:
            alerts.append({"ip": ip, "why": f"successful SSH login from non-allow-listed IP after {a['fails']} failures",
                           "users": [u for u in a["users"]][:5]})
        sc = score(a)
        if sc >= min_score:
            feed.append({"ip": ip, "score": sc, "attempts": a["attempts"], "fails": a["fails"], "invalid_user": a["invalid_user"],
                         "success": a["success"], "distinct_users": len(a["users"]), "top_users": [u for u, _ in a["users"].most_common(5)],
                         "first_seen": a["first_seen"], "last_seen": a["last_seen"], "sources": sorted(a["sources"])})
    feed.sort(key=lambda x: (-x["score"], x["ip"]))
    return feed, alerts, cluster(agg)


def export(feed, alerts, clusters, out):
    from pathlib import Path
    out = Path(out); out.mkdir(exist_ok=True, parents=True)
    (out / "blocklist.txt").write_text("# ssh-threat-feed: score>=threshold; lab data, review before blocking\n" + "\n".join(f["ip"] for f in feed) + "\n")
    with open(out / "feed.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(feed[0].keys()) if feed else ["ip"]); w.writeheader()
        for r in feed:
            w.writerow({**r, "top_users": ";".join(r["top_users"]), "sources": ";".join(r["sources"])})
    json.dump({"feed": feed, "alerts": alerts, "clusters": clusters}, open(out / "feed.json", "w"), indent=2)
    stix_bundle(feed, out / "feed.stix.json")


def stix_bundle(feed, path):
    import stix2
    ident = stix2.Identity(id="identity--6f1f3e4c-6c55-5d2f-9a1e-2b7c7d6a0001", name="ssh-threat-feed (lab)", identity_class="individual")
    objs = [ident]
    for f in feed:
        objs.append(stix2.Indicator(name=f"SSH brute-force source {f['ip']}", pattern=f"[ipv4-addr:value = '{f['ip']}']",
                                    pattern_type="stix", indicator_types=["malicious-activity"], confidence=f["score"],
                                    created_by_ref=ident.id, labels=["ssh-bruteforce"], description=f"fails={f['fails']} users={len(f['top_users'])}"))
    open(path, "w").write(stix2.Bundle(objects=objs, allow_custom=False).serialize(pretty=True))
    return len(objs) - 1
