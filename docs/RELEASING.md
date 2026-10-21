# Release checklist

Releases use the version in `shelter_monitor/__init__.py` and a matching `vX.Y.Z` Git tag. Preserve existing tags and published assets.

1. Review the diff, README translations, sample configuration and image privacy. Do not include real configuration, tokens, databases or original private screenshots.
2. Run the Linux test suite and linters described in the README. Require successful CI for the exact commit, including the Python matrix, ShellCheck, Docker build/smoke test and both compose files.
3. Update `CHANGELOG.md`, commit, and push through the repository's existing branch workflow. Check that no unrelated edits are included.
4. Create a draft release targeting that commit. Package only committed files, using `git archive` with the prefix `shelter-monitor-agent-X.Y.Z/`, in ZIP and tar.gz formats. The tar archive retains executable script permissions.
5. Generate `SHA256SUMS.txt` for the two archives. Extract and inspect the archives; run the suite from the tar archive on Linux. Include the installation scripts, configs, Docker files, README files and documentation assets.
6. Upload archives and checksums, confirm their digests, then publish the release. Verify the public download URLs and checksums and that `releases/latest` points to the intended release.

The downloadable packages contain source and installation scripts. They are not Windows executables or prebuilt container images. Docker images are built locally with `docker compose build`.

For 0.1.0 the asset names are:

```text
shelter-monitor-agent-0.1.0.tar.gz
shelter-monitor-agent-0.1.0.zip
SHA256SUMS.txt
```
