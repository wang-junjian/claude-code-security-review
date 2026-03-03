#!/usr/bin/env python3
"""CLI for scanning entire code repository for security vulnerabilities."""

import argparse
import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

# Import existing components
from claudecode.prompts import get_security_audit_prompt
from claudecode.findings_filter import FindingsFilter
from claudecode.github_action_audit import SimpleClaudeRunner, initialize_findings_filter
from claudecode.logger import get_logger
from claudecode.constants import EXIT_CONFIGURATION_ERROR, EXIT_SUCCESS, EXIT_GENERAL_ERROR


logger = get_logger(__name__)


class RepositoryScanResult:
    """Result of a repository scan."""

    def __init__(self, repo_path: str, findings: List[Dict[str, Any]], analysis_summary: Dict[str, Any]):
        self.repo_path = repo_path
        self.findings = findings
        self.analysis_summary = analysis_summary

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "repo_path": self.repo_path,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "analysis_summary": self.analysis_summary,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


def scan_repository(repo_path: str,
                   custom_filtering_instructions: Optional[str] = None,
                   custom_scan_instructions: Optional[str] = None,
                   verbose: bool = False) -> RepositoryScanResult:
    """Scan entire repository for security vulnerabilities.

    Args:
        repo_path: Path to the repository to scan
        custom_filtering_instructions: Optional custom filtering instructions
        custom_scan_instructions: Optional custom scan instructions
        verbose: Enable verbose logging

    Returns:
        RepositoryScanResult object

    Raises:
        Exception: If scan fails
    """
    try:
        # Validate repository path
        repo_dir = Path(repo_path)
        if not repo_dir.exists() or not repo_dir.is_dir():
            raise ValueError(f"Invalid repository path: {repo_path}")

        logger.info(f"Scanning repository: {repo_path}")

        # Initialize Claude runner
        claude_runner = SimpleClaudeRunner(verbose=verbose)
        claude_ok, claude_error = claude_runner.validate_claude_available()
        if not claude_ok:
            raise Exception(f"Claude Code not available: {claude_error}")

        # Initialize findings filter
        findings_filter = initialize_findings_filter(custom_filtering_instructions)

        # Generate prompt for scanning entire repository
        prompt = generate_full_repository_prompt(repo_dir, custom_scan_instructions)

        # Run security audit
        logger.info("Running security audit on entire repository")
        success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt)
        if not success:
            raise Exception(f"Security audit failed: {error_msg}")

        # Filter findings
        logger.info("Filtering findings to reduce false positives")
        original_findings = results.get('findings', [])

        # Prepare context for filtering (we use empty context for now)
        pr_context = {
            'repo_name': repo_dir.name,
            'pr_number': None,
            'title': 'Full repository scan',
            'description': 'Security scan of entire repository'
        }

        filter_success, filter_results, filter_stats = findings_filter.filter_findings(
            original_findings, pr_context
        )

        if filter_success:
            kept_findings = filter_results.get('filtered_findings', [])
            analysis_summary = filter_results.get('analysis_summary', {})
        else:
            # If filtering fails, keep all findings
            kept_findings = original_findings
            analysis_summary = {}

        logger.info(f"Scan completed. Found {len(kept_findings)} security issues.")

        return RepositoryScanResult(str(repo_dir), kept_findings, analysis_summary)

    except Exception as e:
        logger.error(f"Error scanning repository: {type(e).__name__}: {e}")
        import traceback
        logger.error(f"Error traceback:\n{traceback.format_exc()}")
        raise


def generate_full_repository_prompt(repo_dir: Path, custom_scan_instructions: Optional[str]) -> str:
    """Generate prompt for scanning entire repository.

    Args:
        repo_dir: Path to the repository
        custom_scan_instructions: Optional custom scan instructions

    Returns:
        Generated prompt string
    """
    # Get repository structure
    repo_structure = get_repository_structure(repo_dir)

    # 构建提示文本，使用安全的字符串拼接方法
    prompt = """Please perform a comprehensive security audit of the entire repository structure provided below.

Your task is to identify all potential security vulnerabilities, including but not limited to:

- Code injection vulnerabilities (SQL injection, XSS, command injection)
- Authentication and authorization issues
- Sensitive data exposure
- Security misconfigurations
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- Insecure direct object references
- Broken access control
- Security header issues
- Insecure file handling
- Path traversal vulnerabilities
- Server-side request forgery (SSRF)
- Dependency vulnerabilities
- Configuration management issues

Repository Structure:
```
"""+ repo_structure + """
```

"""+ (custom_scan_instructions if custom_scan_instructions else "") + """

Please provide detailed findings with:
1. Vulnerability type
2. Severity level (HIGH, MEDIUM, LOW)
3. File path
4. Line numbers
5. Detailed description
6. Remediation recommendations

**返回结果的属性值请使用中文，并且保持格式一致。**

Return your findings in JSON format with the following structure:
{
  "findings": [
    {
      "title": "Vulnerability Title",
      "description": "Detailed description",
      "file": "path/to/file",
      "line": 123,
      "severity": "HIGH",
      "vulnerability_type": "Injection",
      "remediation": "Fix recommendation"
    }
  ],
  "analysis_summary": {
    "total_findings": 10,
    "high_severity": 3,
    "medium_severity": 5,
    "low_severity": 2,
    "runtime_seconds": 120.5
  }
}
"""

    return prompt


def get_repository_structure(repo_dir: Path, max_depth: int = 2) -> str:
    """Get repository structure for prompt.

    Args:
        repo_dir: Path to repository
        max_depth: Maximum depth to traverse

    Returns:
        Formatted repository structure string
    """
    structure = []
    for root, dirs, files in os.walk(str(repo_dir)):
        # Skip hidden directories and files
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        files = [f for f in files if not f.startswith('.')]

        # Calculate current depth
        current_depth = root[len(str(repo_dir)):].count(os.sep)

        if current_depth > max_depth:
            continue

        # Add current directory
        depth_prefix = "  " * current_depth
        relative_path = root[len(str(repo_dir)):].strip(os.sep)
        if relative_path:
            structure.append(f"{depth_prefix}{relative_path}/")
        else:
            structure.append("./")

        # Add files
        for file in sorted(files):
            file_path = os.path.join(root, file)
            # Skip large files
            if os.path.getsize(file_path) > 100000:  # 100KB
                continue
            # Skip binary files
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    # If we can read the file as text, include it
                    structure.append(f"{depth_prefix}  {file}")
            except UnicodeDecodeError:
                continue

    return '\n'.join(structure)


def main():
    """Main entry point for repository scan."""
    parser = argparse.ArgumentParser(
        description="Scan entire code repository for security vulnerabilities",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "repo_path",
        help="Path to the repository to scan (current directory if not specified)",
        nargs='?',
        default=os.getcwd()
    )

    parser.add_argument(
        "--output", "-o",
        help="Output file to save scan results (stdout if not specified)",
        type=str,
        default=None
    )

    parser.add_argument(
        "--verbose", "-v",
        help="Enable verbose logging",
        action="store_true"
    )

    parser.add_argument(
        "--filtering-instructions",
        help="Path to custom filtering instructions file",
        type=str,
        default=None
    )

    parser.add_argument(
        "--scan-instructions",
        help="Path to custom scan instructions file",
        type=str,
        default=None
    )

    args = parser.parse_args()

    # Load custom instructions
    custom_filtering_instructions = None
    if args.filtering_instructions:
        filtering_file = Path(args.filtering_instructions)
        if filtering_file.exists() and filtering_file.is_file():
            try:
                with open(filtering_file, 'r', encoding='utf-8') as f:
                    custom_filtering_instructions = f.read()
            except Exception as e:
                logger.error(f"Failed to read filtering instructions file: {e}")
                sys.exit(EXIT_CONFIGURATION_ERROR)
        else:
            logger.error(f"Filtering instructions file not found: {args.filtering_instructions}")
            sys.exit(EXIT_CONFIGURATION_ERROR)

    custom_scan_instructions = None
    if args.scan_instructions:
        scan_file = Path(args.scan_instructions)
        if scan_file.exists() and scan_file.is_file():
            try:
                with open(scan_file, 'r', encoding='utf-8') as f:
                    custom_scan_instructions = f.read()
            except Exception as e:
                logger.error(f"Failed to read scan instructions file: {e}")
                sys.exit(EXIT_CONFIGURATION_ERROR)
        else:
            logger.error(f"Scan instructions file not found: {args.scan_instructions}")
            sys.exit(EXIT_CONFIGURATION_ERROR)

    try:
        scan_result = scan_repository(
            args.repo_path,
            custom_filtering_instructions=custom_filtering_instructions,
            custom_scan_instructions=custom_scan_instructions,
            verbose=args.verbose
        )

        scan_result_dict = scan_result.to_dict()

        if args.output and args.output != "-":
            output_path = Path(args.output)
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(scan_result_dict, f, indent=2, ensure_ascii=False)
                logger.info(f"Results saved to: {args.output}")
            except Exception as e:
                logger.error(f"Failed to save results to file: {e}")
                sys.exit(EXIT_GENERAL_ERROR)
        else:
            print(json.dumps(scan_result_dict, indent=2, ensure_ascii=False))

        # Return exit code based on findings count
        if len(scan_result.findings) > 0:
            sys.exit(EXIT_GENERAL_ERROR)
        else:
            sys.exit(EXIT_SUCCESS)

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(json.dumps({'error': str(e)}))
        sys.exit(EXIT_GENERAL_ERROR)


if __name__ == "__main__":
    main()
