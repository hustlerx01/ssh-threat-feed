import argparse, json
from pathlib import Path
from .ingest import parse_authlog, parse_cowrie
from .feed import build, export


def main(argv=None):
    ap = argparse.ArgumentParser(description="SSH honeypot / auth.log -> threat feed")
    ap.add_argument("--authlog", nargs="*", default=[]); ap.add_argument("--cowrie", nargs="*", default=[])
    ap.add_argument("--min-score", type=int, default=30); ap.add_argument("-o", "--out", default="results")
    a = ap.parse_args(argv)
    ev = []
    for p in a.authlog: ev += parse_authlog(open(p, errors="replace"), source=Path(p).name)
    for p in a.cowrie: ev += parse_cowrie(open(p))
    feed, alerts, clusters = build(ev, a.min_score)
    export(feed, alerts, clusters, a.out)
    print(f"events={len(ev)} unique_ips={len({e['src_ip'] for e in ev})} feed_ips={len(feed)} success_alerts={len(alerts)} playbook_clusters={len(clusters)}")
    for f in feed[:10]:
        print(f"  {f['ip']:16s} score={f['score']:3d} fails={f['fails']:4d} users={f['distinct_users']:3d} top={f['top_users'][:3]}")
    for al in alerts: print("  ALERT", json.dumps(al))
    for c in clusters[:5]: print("  cluster", c)


if __name__ == "__main__":
    main()
