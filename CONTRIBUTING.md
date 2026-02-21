# Contributing to Lifeguard

Welcome to Lifeguard! We are committed to building a secure, tool-aware agent verification framework and appreciate your interest in contributing.

## Contributor License Agreement (CLA)

By contributing to this project, you agree that your contributions are licensed under the [Business Source License 1.1](LICENSE) (BSL) for the community edition and will transition to the [Apache License 2.0](LICENSE) on the Change Date (February 21, 2029).

For significant contributions, you may be required to sign a Contributor License Agreement (CLA) to ensure we can protect the project's hybrid licensing model and provide commercial support to our users.

## Code of Conduct

Please be respectful and professional in all interactions. We aim to foster a collaborative environment focused on security and engineering excellence.

## How to Contribute

1.  **Report Bugs:** Use our [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md) for reporting issues.
2.  **Suggest Features:** We welcome ideas! Open a [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md).
3.  **Submit Pull Requests:**
    - Fork the repository and create a new branch.
    - Ensure all tests pass (`pytest tests`).
    - Run the validation pipeline (`python3 scripts/run_completion_validation.py`) for major changes.
    - Follow our [Adapter Migration Policy](docs/ADAPTER_MIGRATION_POLICY.md) if modifying integration layers.
    - Keep commits focused and provide clear descriptions.

## Security Vulnerabilities

**Do not report security vulnerabilities through public GitHub issues.** Please refer to our [SECURITY.md](SECURITY.md) for responsible disclosure procedures.
