# Falco Runtime Detection Evidence

## Detections triggered in lab (2026-05-17)

All detections were intentionally generated in a test pod (`shellme`, `cred-test`)
in the `security` namespace to verify Falco rules are working.

| File | Rule | Priority | ATT&CK | Description |
|---|---|---|---|---|
| `falco-shell-alert.json` | Terminal shell in container | NOTICE | T1059 / mitre_execution | `kubectl exec -it shellme -- sh` |
| `falco-sensitive-file.json` | Read sensitive file untrusted | WARNING | T1555 / mitre_credential_access | `cat /etc/shadow` inside container |
| `falco-package-manager.json` | Package manager run in container | WARNING | T1072 / mitre_lateral_movement | `apk add curl` — custom rule |
| `falco-binary-drop.json` | Drop and execute new binary | CRITICAL | mitre_persistence | curl binary downloaded and executed |
| `falco-ui-screenshot.png` | All four rules | — | — | Falcosidekick UI showing detections |

## Custom rules

Two custom rules were written for this lab (`manifests/05-runtime/falco-values.yaml`):

1. **Package manager run in container** — maps `apk`, `apt`, `apt-get`, etc. to T1072
2. **Cloud credential file read** — detects reads of `.aws/credentials`, `.mc/config.json`, etc.; maps to T1552.001

## Noise notes

Longhorn's `backup cleanup-all-mounts` process generates continuous false positives
on the "Redirect STDOUT/STDIN to Network Connection" rule via `dup3` syscalls.
This is legitimate storage behavior. Suppressed in production via Falco rule exception
(see `manifests/05-runtime/falco-values.yaml` `customRules:` block).
