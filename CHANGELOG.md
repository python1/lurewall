# Changelog

## 0.4.1

- Agent identity checks ignore crawler names introduced by the word `like` in a User-Agent. A separate claim in the same header is still checked.
- `lurewall doctor` explains when the service account lacks permission to inspect nftables. A successful query identifies whether the managed table exists, and probe faults retain their diagnostic details.

Created by Paul Charydczak
