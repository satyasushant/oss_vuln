# Main: Entry point for the OSS Vulnerability Remediation Pipeline.
# Orchestrates the full flow:
#   1. scanner.py       - scans project using jf audit
#   2. parser.py        - cleans and filters vulnerabilities by severity
#   3. agent.py         - AI agent fixes vulnerabilities intelligently
#   4. chain_analyzer.py - finds smartest fix strategy per vulnerability
#   5. parent_checker.py - checks and updates parent version
#   6. dep_updater.py   - updates direct dependency versions
# Change REPO_PATH to point to any microservice to scan and fix.

import asyncio
import argparse
from scanner import scan_project
from parser import extract_vulnerabilities, save_vulnerabilities
# from agent import create_agent
# from google.adk.runners import Runner
# from google.adk.sessions import InMemorySessionService
# from google.genai import types

def get_args():
    parser = argparse.ArgumentParser(description="OSS Vulnerability Remediation Pipeline")
    parser.add_argument("--repo-path", required=True, help="Full path to project with pom.xml")
    parser.add_argument("--min-severity", default="High", choices=["Low", "Medium", "High", "Critical"])
    return parser.parse_args()

def main():
    args = get_args()
    REPO_PATH = args.repo_path
    MIN_SEVERITY = args.min_severity

    print("=" * 50)
    print("OSS Vulnerability Remediation Pipeline")
    print("=" * 50)
    print(f"Project   : {REPO_PATH}")
    print(f"Min Severity: {MIN_SEVERITY}")
    print("=" * 50)

    # Step 1 - Scan
    scan_data = scan_project(REPO_PATH)

    # Step 2 - Parse
    vulnerabilities = extract_vulnerabilities(scan_data, MIN_SEVERITY)
    save_vulnerabilities(vulnerabilities)

    if not vulnerabilities:
        print("No vulnerabilities found!")
        return

    print(f"Found {len(vulnerabilities)} vulnerabilities - saved to filtered-vulns.json")

    # Step 3 and 4 - Agent (uncomment when ADK is ready)
    # agent = create_agent(REPO_PATH, vulnerabilities)
    # ...

if __name__ == "__main__":
    main()