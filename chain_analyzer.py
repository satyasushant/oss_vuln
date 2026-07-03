import os
import xml.etree.ElementTree as ET

# Chain Analyzer: Analyzes dependency chain to find the smartest fix point.
# Works for ANY project with ANY parent - not hardcoded to any specific parent.
# Priority:
#   1. If vulnerable dependency directly in pom.xml → update version directly
#   2. If not in pom.xml → must come from parent → check/bump parent
#   3. If parent already latest but still vulnerable → ask user

def analyze_chain(repo_path: str, vulnerability: dict) -> dict:
    chain = vulnerability.get("dependency_chain", [])
    pom_path = os.path.join(repo_path, "pom.xml")

    ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
    ns = {"maven": "http://maven.apache.org/POM/4.0.0"}
    tree = ET.parse(pom_path)
    root = tree.getroot()

    # Get parent info - whatever parent it is
    parent = root.find("maven:parent", ns)
    parent_artifact = parent.find("maven:artifactId", ns).text if parent else None
    parent_version = parent.find("maven:version", ns).text if parent else None
    parent_group = parent.find("maven:groupId", ns).text if parent else None

    # Get all direct dependencies with versions from pom.xml
    direct_deps = {}
    for dep in root.findall(".//maven:dependency", ns):
        artifact = dep.find("maven:artifactId", ns)
        version = dep.find("maven:version", ns)
        group = dep.find("maven:groupId", ns)
        if artifact is not None:
            direct_deps[artifact.text] = {
                "version": version.text if version is not None else None,
                "group": group.text if group is not None else None
            }

    # Walk through chain skip first - that's your project
    for item in chain[1:]:
        parts = item.split(":")
        artifact = parts[0]

        # Scenario 1 - directly in pom.xml with explicit version
        if artifact in direct_deps and direct_deps[artifact]["version"] is not None:
            return {
                "strategy": "UPDATE_DIRECT_DEPENDENCY",
                "fix_artifact": artifact,
                "fix_group": direct_deps[artifact]["group"],
                "current_version": direct_deps[artifact]["version"],
                "message": f"{artifact} found directly in pom.xml - update version"
            }

        # Scenario 2 - NOT in pom.xml → comes from parent (any parent)
        if artifact not in direct_deps and parent_artifact:
            return {
                "strategy": "BUMP_PARENT",
                "fix_artifact": parent_artifact,
                "fix_group": parent_group,
                "current_version": parent_version,
                "message": f"{artifact} not in pom.xml - comes from parent {parent_artifact}:{parent_version}"
            }

    # Scenario 3 - parent already latest, still vulnerable → ask user
    print(f"\n{'='*60}")
    print(f"Manual Decision Required")
    print(f"{'='*60}")
    print(f"Vulnerability : {vulnerability['artifact']}:{vulnerability['current_version']}")
    print(f"Severity      : {vulnerability['severity']}")
    print(f"CVEs          : {', '.join(vulnerability.get('cve_ids', []))}")
    print(f"Fixed versions: {vulnerability.get('fixed_versions', [])}")
    print(f"\nDependency chain:")
    print(f"  {' -> '.join(vulnerability.get('dependency_chain', []))}")
    print(f"\nParent {parent_artifact}:{parent_version} is already at latest version.")
    print(f"This indirect dependency is still vulnerable.")
    print(f"\nWhat do you want to do?")
    print(f"1) Add explicit version override in dependencyManagement")
    print(f"2) Leave it as is (skip)")
    print(f"{'='*60}")

    choice = input("Enter choice (1 or 2): ").strip()

    if choice == "1":
        return {
            "strategy": "DIRECT_OVERRIDE",
            "fix_artifact": vulnerability["artifact"],
            "fix_group": vulnerability["group"],
            "current_version": vulnerability["current_version"],
            "message": f"User chose direct override for {vulnerability['artifact']}"
        }
    else:
        return {
            "strategy": "SKIP",
            "fix_artifact": vulnerability["artifact"],
            "message": f"User chose to skip {vulnerability['artifact']}"
        }