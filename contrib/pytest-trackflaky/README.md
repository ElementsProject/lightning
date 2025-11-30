# pytest-trackflaky

A pytest plugin to track and report test flakiness to a central server.

## Features

- Automatically tracks test execution times and outcomes
- Collects GitHub Actions metadata (commit SHA, branch, run ID, etc.)
- Reports test results to a configurable server endpoint
- Zero configuration needed when running in CI environments

## Installation

Install the plugin using pip or uv:

```bash
pip install -e contrib/pytest-trackflaky
```

Or with uv:

```bash
uv pip install -e contrib/pytest-trackflaky
```

## Usage

Once installed, the plugin is automatically activated when running pytest. No additional configuration is needed.

### Configuration

The plugin is controlled via environment variables:

- `CI_SERVER_URL`: The base URL of the server to report results to (required for reporting)
  - Test results will be POSTed to `{CI_SERVER_URL}/hook/test`
- `GITHUB_*`: Standard GitHub Actions environment variables are automatically collected

### Example

```bash
export CI_SERVER_URL="https://your-flaky-tracker.example.com"
pytest
```

## Data Collected

For each test, the plugin collects:

- Test name
- Outcome (success/skip/fail)
- Start and end times
- GitHub repository information
- Git commit SHA and branch
- GitHub Actions run metadata

## Development

To work on the plugin locally:

```bash
cd contrib/pytest-trackflaky
pip install -e .
```
