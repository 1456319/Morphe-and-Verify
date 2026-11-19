## Morphe-and-Verify v2.6.0

Initial release of Morphe-and-Verify featuring the three-pillar patch effectiveness verification engine ported from MP-Manager.

### Notice
This project is an independent fork and has no affiliation with or endorsement from MorpheApp.

### Highlights
- Strict patch verification: patches are only verified as applied if target methods exist, are reachable, and caller pathways are mapped.
- Multi-DEX reachability tracing and compound fallback detection.
- Honest reporting: YES / NO / MAYBE status breakdown instead of false successes.
- In-app update checker configured to fetch releases and changelogs directly from this repository.
