# GitHub Workflows

This directory contains GitHub Actions workflows for the KProxy project.

## Note on `workflows/release.yml`

The `release.yml` workflow file exists locally but cannot be pushed via the GitHub API due to workflow permissions restrictions.

**To add this workflow to the repository:**

1. After merging the GoReleaser PR, manually add the workflow file:
   ```bash
   git checkout claude/add-goreleaser-config-nFpkt
   git add .github/workflows/release.yml
   git commit -m "Add GitHub Actions release workflow"
   git push
   ```

2. Or create it through the GitHub web interface using the content from `workflows/release.yml`

The workflow will enable automated releases when version tags are pushed to the repository.
