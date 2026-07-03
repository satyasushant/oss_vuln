from typing import Dict, List
from google.adk import Agent
from fixer import apply_pom_fixes
from builder import run_maven_build
from chain_analyzer import analyze_chain
from parent_checker import get_current_parent, update_parent_version
from dep_updater import update_direct_dependency

# Agent: Creates an AI agent that autonomously fixes vulnerable Maven dependencies.
# The AI decides which strategy to use based on chain analysis.
# Strategies: UPDATE_DIRECT_DEPENDENCY, BUMP_PARENT, DIRECT_OVERRIDE, SKIP
# Tools provided to AI:
#   - scan_workspace_dependencies: returns vulnerabilities with dependency chains
#   - get_fix_strategy: analyzes chain and returns best fix strategy
#   - update_dependency: updates direct dependency version in pom.xml
#   - check_and_bump_parent: checks and updates parent version
#   - fetch_and_apply_safe_versions: adds direct override in dependencyManagement
#   - verify_build: runs mvn clean test and returns SUCCESS or FAILED

def create_agent(repo_path: str, vulnerabilities: list) -> Agent:

    def scan_workspace_dependencies() -> List[Dict]:
        """Returns all vulnerable libraries with dependency chains and fixed versions."""
        return [
            {
                "vulnerable_lib": f"{v['group']}:{v['artifact']}",
                "current_version": v["current_version"],
                "fixed_versions": v["fixed_versions"],
                "severity": v["severity"],
                "dependency_chain": v.get("dependency_chain", [])
            }
            for v in vulnerabilities
        ]

    def get_fix_strategy(vulnerable_lib: str) -> dict:
        """Analyzes dependency chain and returns best fix strategy for a vulnerability."""
        matching = [
            v for v in vulnerabilities
            if f"{v['group']}:{v['artifact']}" == vulnerable_lib
        ]
        if not matching:
            return {"strategy": "NOT_FOUND", "message": f"{vulnerable_lib} not found"}
        return analyze_chain(repo_path, matching[0])

    def update_dependency(group_id: str, artifact_id: str, new_version: str) -> str:
        """Updates a direct dependency version in pom.xml."""
        return update_direct_dependency(repo_path, group_id, artifact_id, new_version)

    def check_and_bump_parent(new_version: str) -> str:
        """Updates parent version in pom.xml."""
        return update_parent_version(repo_path, new_version)

    def get_parent_info() -> dict:
        """Returns current parent artifact and version from pom.xml."""
        return get_current_parent(repo_path)

    def fetch_and_apply_safe_versions(lib: str, version: str) -> str:
        """Applies a specific version override in dependencyManagement."""
        parts = lib.split(":")
        if len(parts) != 2:
            return f"Error: malformed lib {lib}"
        group_id, artifact_id = parts
        return apply_pom_fixes(repo_path, group_id, artifact_id, version)

    def verify_build() -> str:
        """Runs mvn clean test to verify fixes."""
        return run_maven_build(repo_path)

    agent = Agent(
        name="OSSRemediationAgent",
        model="ollama/qwen2.5:1.5b",
        instruction=(
            "You are an autonomous Java security engineer. "
            "Fix vulnerable Maven dependencies intelligently. "
            "Follow these steps for EACH vulnerability: "
            "1. Call scan_workspace_dependencies to get all vulnerabilities. "
            "2. For each vulnerable lib call get_fix_strategy to get strategy. "
            "3. Follow the strategy returned: "
            "   UPDATE_DIRECT_DEPENDENCY: "
            "       a. Call update_dependency with fix_artifact, fix_group and lowest fixed version. "
            "       b. Call verify_build to confirm. "
            "       c. If FAILED try next fixed version and repeat. "
            "   BUMP_PARENT: "
            "       a. Call get_parent_info to get current parent. "
            "       b. Ask user for latest parent version or check Artifactory. "
            "       c. Call check_and_bump_parent with new version. "
            "       d. Call verify_build to confirm. "
            "       e. If still vulnerable call get_fix_strategy again as fallback. "
            "   DIRECT_OVERRIDE: "
            "       a. User already approved this. "
            "       b. Call fetch_and_apply_safe_versions with lib and lowest fixed version. "
            "       c. Call verify_build to confirm. "
            "       d. If FAILED try next fixed version and repeat. "
            "   SKIP: "
            "       a. User chose to skip. Move to next vulnerability. "
            "4. After all vulnerabilities call verify_build one final time. "
            "5. Report: "
            "   - Fixed via direct dependency update. "
            "   - Fixed via parent bump. "
            "   - Fixed via direct override. "
            "   - Skipped by user."
        ),
        tools=[
            scan_workspace_dependencies,
            get_fix_strategy,
            update_dependency,
            check_and_bump_parent,
            get_parent_info,
            fetch_and_apply_safe_versions,
            verify_build
        ]
    )

    return agent