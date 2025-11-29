#!/usr/bin/env python3
"""
Generate Python API documentation for all workspace packages using pdoc3.

This script generates HTML documentation for all Python packages in the
Core Lightning workspace and creates an index page linking to all of them.
"""

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Define packages to document (module name -> source directory)
# Only includes packages that are in the workspace and can be imported
PACKAGES = {
    "pyln.client": "contrib/pyln-client",
    "pyln.proto": "contrib/pyln-proto",
    "pyln.grpc": "contrib/pyln-grpc-proto",
    "pyln.testing": "contrib/pyln-testing",
    "pyln.spec.bolt7": "contrib/pyln-spec/bolt7",
}

INDEX_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Core Lightning Python Packages Documentation</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
            line-height: 1.6;
        }}
        h1 {{
            border-bottom: 2px solid #eaecef;
            padding-bottom: 0.3em;
        }}
        .package-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }}
        .package-card {{
            border: 1px solid #e1e4e8;
            border-radius: 6px;
            padding: 20px;
            transition: box-shadow 0.2s;
        }}
        .package-card:hover {{
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        .package-card h2 {{
            margin-top: 0;
            font-size: 1.3em;
        }}
        .package-card a {{
            color: #0366d6;
            text-decoration: none;
        }}
        .package-card a:hover {{
            text-decoration: underline;
        }}
        .package-description {{
            color: #586069;
            font-size: 0.9em;
            margin-top: 8px;
        }}
        .timestamp {{
            color: #586069;
            font-size: 0.9em;
            margin-top: 30px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <h1>Core Lightning Python Packages Documentation</h1>
    <p>This page provides links to the API documentation for all Python packages in the Core Lightning workspace.</p>

    <div class="package-grid">
        <div class="package-card">
            <h2><a href="pyln/client/index.html">pyln.client</a></h2>
            <p class="package-description">Client library and plugin library for Core Lightning</p>
        </div>

        <div class="package-card">
            <h2><a href="pyln/proto/index.html">pyln.proto</a></h2>
            <p class="package-description">Lightning Network protocol implementation</p>
        </div>

        <div class="package-card">
            <h2><a href="pyln/grpc/index.html">pyln.grpc</a></h2>
            <p class="package-description">gRPC protocol definitions for Core Lightning</p>
        </div>

        <div class="package-card">
            <h2><a href="pyln/testing/index.html">pyln.testing</a></h2>
            <p class="package-description">Testing utilities for Core Lightning</p>
        </div>

        <div class="package-card">
            <h2><a href="pyln/spec/bolt7/index.html">pyln.spec.bolt7</a></h2>
            <p class="package-description">BOLT #7 specification implementation</p>
        </div>
    </div>

    <p class="timestamp">Generated on {timestamp}</p>
</body>
</html>
"""


def generate_docs(output_dir: Path, repo_root: Path):
    """Generate documentation for all packages."""
    print(f"Generating Python documentation for all workspace packages...")
    print(f"Output directory: {output_dir}")

    # Clean and create output directory
    if output_dir.exists():
        import shutil
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    # Change to repo root for imports to work correctly
    os.chdir(repo_root)

    # Generate documentation for each package
    for package, source_dir in PACKAGES.items():
        print(f"Generating docs for {package} (from {source_dir})...")

        try:
            # Use pdoc3 to generate HTML documentation
            subprocess.run(
                [
                    "uv", "run", "pdoc3",
                    "--html",
                    "--output-dir", str(output_dir),
                    "--force",
                    package
                ],
                check=True,
                cwd=repo_root,
            )
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed to generate docs for {package}, skipping...")
            print(f"Error: {e}")
            continue

    # Create index.html
    index_path = output_dir / "index.html"
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    index_path.write_text(INDEX_HTML_TEMPLATE.format(timestamp=timestamp))

    print("\nDocumentation generated successfully!")
    print(f"Open {output_dir}/index.html in your browser to view the documentation.")


def main():
    """Main entry point."""
    # Determine paths
    script_dir = Path(__file__).parent.resolve()
    repo_root = script_dir.parent.parent

    # Default output directory
    output_dir = repo_root / "docs" / "python"

    # Allow override via command line argument
    if len(sys.argv) > 1:
        output_dir = Path(sys.argv[1])

    generate_docs(output_dir, repo_root)


if __name__ == "__main__":
    main()
