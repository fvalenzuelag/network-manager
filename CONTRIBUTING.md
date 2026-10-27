# Contributing to Network Management Tool

Thank you for your interest in contributing to the Network Management Tool! We welcome contributions from everyone, whether it's reporting bugs, suggesting improvements, or submitting code changes. By following these guidelines, you'll help us make the project better for everyone.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing to this project. By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository on GitHub.
2. Clone your forked repository to your local machine:
    ```
    git clone https://github.com/fvalenzuelag/network-management-tool.git
    ```

3. Create a new branch for your changes:
    ```
    git checkout -b my-new-feature
    ```

4. Make your changes, adding tests if applicable, and run the suite
   (stdlib only, no network needed):
    ```
    python3 -m unittest discover tests
    ```
   GitHub Actions runs the same tests on macOS and Linux (Python 3.10 and
   latest) for every pull request, plus a smoke run of the real full check.

5. Commit your changes with a descriptive commit message:
    ```
    git commit -am "Add a new feature"
    ```

6. Push your changes to your forked repository:
    ```
    git push origin my-new-feature
    ```

7. Create a new pull request from your forked repository to the main repository.

## Pull Request Guidelines

- Ensure that your code follows the project's coding style and conventions.
- Include tests for any new functionality or bug fixes.
- Update the documentation if necessary.
- Describe your changes in detail in the pull request description.
- Be responsive to feedback and make any requested changes.

## Bug Reports

If you find a bug in the project, please create a new issue on the repository and provide the following information:

- A clear and descriptive title for the issue.
- A detailed description of the problem, including steps to reproduce it.
- The expected behavior and the actual behavior.
- Any relevant error messages or logs.
- Your environment details (operating system, Python version, etc.).

## Feature Requests

If you have an idea for a new feature or an improvement to an existing one, please create a new issue on the GitHub repository and provide the following information:

- A clear and descriptive title for the feature request.
- A detailed description of the proposed feature or improvement.
- The motivation behind the request and the expected benefits.
- Any relevant examples or use cases.

## Code Style

This project follows the [PEP 8](https://www.python.org/dev/peps/pep-0/) style guide for Python code. Please ensure that your contributions adhere to these guidelines.

## License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).