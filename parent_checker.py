import os
import xml.etree.ElementTree as ET

# Parent Checker: Checks and updates parent version in pom.xml.
# Generic - works for any parent not just quarkus.

def get_current_parent(repo_path: str) -> dict:
    """Reads current parent version from pom.xml"""
    pom_path = os.path.join(repo_path, "pom.xml")
    ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
    ns = {"maven": "http://maven.apache.org/POM/4.0.0"}
    tree = ET.parse(pom_path)
    root = tree.getroot()

    parent = root.find("maven:parent", ns)
    if parent is None:
        return {"error": "No parent found in pom.xml"}

    return {
        "group_id": parent.find("maven:groupId", ns).text,
        "artifact_id": parent.find("maven:artifactId", ns).text,
        "version": parent.find("maven:version", ns).text
    }

def update_parent_version(repo_path: str, new_version: str) -> str:
    """Updates parent version in pom.xml"""
    pom_path = os.path.join(repo_path, "pom.xml")
    ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
    ns = {"maven": "http://maven.apache.org/POM/4.0.0"}
    tree = ET.parse(pom_path)
    root = tree.getroot()

    parent = root.find("maven:parent", ns)
    if parent is None:
        return "Error: No parent found in pom.xml"

    version_element = parent.find("maven:version", ns)
    old_version = version_element.text
    version_element.text = new_version

    tree.write(pom_path, encoding="utf-8", xml_declaration=True)
    print(f"[ParentChecker] Updated parent version {old_version} -> {new_version}")
    return f"Parent version updated from {old_version} to {new_version}"