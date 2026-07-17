#!/usr/bin/env bash
# Splunk's free tier disables REST/remote login. Run this to re-enable it so
# scripts/run_rule.py keeps working after the 60-day trial reverts to Free.
set -euo pipefail
docker exec -u splunk tdl-splunk bash -lc '
  printf "\n[general]\nallowRemoteLogin = always\n" >> /opt/splunk/etc/system/local/server.conf'
docker exec -u splunk tdl-splunk /opt/splunk/bin/splunk restart
echo "✓ remote login enabled"
