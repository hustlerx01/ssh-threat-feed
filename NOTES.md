# Interview talking points: ssh-threat-feed

1. **Story.** SSH-Log-Alert (my first project) alerted on successful logins. That's detection *after* compromise. This project uses the failures that come *before* it and turns them into shareable intel. Same problem, one level up.
2. **Scoring over thresholds.** Volume alone ranks a noisy misconfigured client above a careful attacker. I weight a success after failures (+30) and post-login commands (+10) above raw counts. A test makes sure a brute force followed by `wget|sh` lands in the feed even with only 8 failures.
3. **Playbook clustering.** Jaccard similarity on username sets. It found 103.207.39.16 and .212 in real data. That's useful for blocking the whole campaign, and it's how ShardLure-style tools attribute botnets.
4. **Feed formats.** txt for iptables/fail2ban, CSV for analysts, STIX 2.1 Indicators (`[ipv4-addr:value = '...']`) with confidence = score, for MISP/OpenCTI.
5. **Feed hygiene.** IPs age out, CGNAT/cloud IPs get recycled, and blocking shared IPs causes outages. Next steps: TTL / decay on scores, and allow-listing cloud provider ranges with review.
6. **Parsing gotchas.** auth.log has no year, `pam_unix` lines may carry a hostname as rhost, and "invalid user" with an empty name produces `Invalid user  from`. My regexes handle these and are unit-tested.
