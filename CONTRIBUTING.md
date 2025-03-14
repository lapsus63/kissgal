# Contributing to Project

Thank you for considering contributing to this project! Here are some guidelines to help you get started.

## Branching Strategy

- We use [GitHub Flow](https://guides.github.com/introduction/flow/).
- **Feature branches**: `feat/FeatureName` - create a pull request to `main` after tests pass.
- **Fix branches**: `fix/FixName` - create a pull request to `main` after tests pass.
- **Snapshot tags**: No tags for snapshots.

## Merge Requests

- Ensure the pipeline is green (unit tests, integration tests, code quality checks) before merging.
- A different developer should review and approve the merge request.
- Follow the merge request template provided in the repository.

## Development

- **IDEs**: Recommended IDEs are `IntelliJ IDEA` and `VSCode`.
- **Plugins**: Recommended plugins are `SonarLint` and `JFrog`.
- **Unit Testing**: Use `JUnit` for unit tests and integration tests.
- **Code Coverage**: Ensure code coverage is tracked using SonarQube and Xray.

## Database

- Configure `DBeaver` for PostgreSQL development and embedded PostgreSQL for tests.
  - Note: The database name and port for embedded PostgreSQL may change; check the logs for details.

## Code Style

- Follow the coding standards and style guides provided in the repository.
- Use `Checkstyle` for Java and `ESLint` for JavaScript/TypeScript.

## Commit Messages

- Use clear and descriptive commit messages.
- Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.

## Reporting Issues

- Use the issue tracker to report bugs or request features.
- Provide as much detail as possible, including steps to reproduce the issue.

## Pull Request Process

1. Fork the repository.
2. Create a new branch (`feat/FeatureName` or `fix/FixName`).
3. Make your changes.
4. Ensure all tests pass.
5. Submit a pull request to the `main` branch.

Thank you for your contributions!
