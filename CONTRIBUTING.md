# Contributing

Thank you for your interest in contributing to `security.compliance_windows`.

## Getting Started

1. Fork the repository and clone your fork.
2. Create a feature branch from `main`.
3. Make your changes and ensure CI passes.
4. Open a pull request against `main`.

## Development Setup

```bash
# Install dependencies
pip install ansible-core ansible-lint ruff

# Install collection dependencies
ansible-galaxy collection install ansible.windows community.windows

# Run linters
ansible-lint --profile production
ruff check plugins/
ruff format --check plugins/
```

## Branch Protection

The `main` branch requires:

- All CI checks to pass (Lint, Python Lint, Sanity 2.16, Sanity 2.17)
- At least one approving review from a maintainer

PRs from the repository owner are auto-approved and auto-merged after CI passes.

## What to Contribute

### Crosswalk Profiles

New regulatory framework crosswalks are the highest-value contribution. To add one:

1. Create a YAML file in `compliance_profiles/` following the existing `hipaa.yml` or `pci_dss_v4.yml` format.
2. Each control must map to CIS and/or STIG rule IDs, or be flagged as a `gap` with a `gap_note`.
3. Add a corresponding scan playbook in `playbooks/`.
4. Update `galaxy.yml` tags and description.

### Filter Plugins

Filter plugins live in `plugins/filter/` and must:

- Pass `ruff check` and `ruff format`
- Pass `ansible-test sanity` for ansible-core 2.16 and 2.17
- Include a docstring on each public method

### Roles

Roles must:

- Use the role name as a variable prefix (e.g., `compliance_crosswalk_` for the `compliance_crosswalk` role)
- Include `meta/main.yml` with author, license, and platform info
- Include `meta/argument_specs.yml` documenting all parameters
- Include `defaults/main.yml` for all configurable parameters
- Pass `ansible-lint --profile production`

### PowerShell Scripts

PowerShell files in `roles/*/files/` must:

- Use `-LiteralPath` instead of `-Path` for file operations
- Follow PSScriptAnalyzer formatting rules (brace placement, whitespace)
- Pass `ansible-test sanity` pslint checks

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
feat: add SOC 2 crosswalk profile
fix: handle empty findings in crosswalk_summary filter
ci: add sanity test for ansible-core 2.18
docs: update CHANGELOG for 1.1.0 release
```

## Code of Conduct

This project follows the [Ansible Community Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html).
