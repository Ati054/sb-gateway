# Build Storage

Before a large local compile or image build, check both the workspace disk and
the disk containing Docker and temporary files. On Windows with WSL, use:

```powershell
node scripts/check-build-space.mjs --wsl <distribution> -- wsl.exe --distribution <distribution> --user root --cd / --exec bash <build-script>
```

The wrapper requires at least 8 GiB available on every checked filesystem and
does not run the build if a disk check fails. It neither deletes files nor
restarts services. Run it before each large build phase; it is an admission
check, not a reservation against concurrent disk writers. A larger build may
need a higher `--min-free-gib` value.

Without `--wsl`, only local paths are checked. Repeat `--path` for additional
output volumes and `--wsl-path` for nondefault guest storage paths. A command
after `--` runs only after all checks pass, with its exit status preserved.
The WSL disk query starts from the Windows system directory and guest root;
the build command retains the caller's working directory.

Use one reusable Go build cache rather than keeping separate release caches.
For Linux compilation, keep that cache on the Linux filesystem rather than
duplicating it in the mounted Windows workspace.
Retain current verified artifacts; remove obsolete intermediate images and
inactive caches after inspecting ownership and container references. Shared
Docker hosts must not be cleaned with an unfiltered system-wide prune. BuildKit
garbage collection is useful but does not replace the pre-build disk check.
