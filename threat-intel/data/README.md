The catalogue the simulated Threat Intel serves. The CVE ids and the products they
affect are real; scores and version ranges are simplified from NVD so the
dataset stays small and readable. Do not treat it as vulnerability intelligence.

- `products.json`: what Threat Intel can turn into a CPE. `aliases` are the names
  agents report (`sshd`, `apache2`...), `name`/`vendor` are the CPE parts.
- `cves.json`: one entry per CVE with the NVD-style version ranges
  (`version_start_including`, `version_end_excluding`...) it applies to.
