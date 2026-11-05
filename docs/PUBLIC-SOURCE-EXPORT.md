# Public source export

Create the release source from a clean committed checkout:

```powershell
./scripts/export-public-source.ps1 -OutputDirectory dist/public-source
```

The export excludes private automation, environment-specific verification and
internal research comparisons. It retains generic product documentation and
sanitized reproducible tests. The public changelog replaces the workspace
changelog, and only the current version's release note is included.

Review both the extracted source and the resulting ZIP before publishing.
Filename exclusions and automated marker checks do not replace content review.
Exporting a clean snapshot does not sanitize existing public Git history or
previously uploaded release assets; audit those separately before publication.
