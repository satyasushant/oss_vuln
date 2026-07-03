import os
import xml.etree.ElementTree as ET

# Dep Updater: Updates a direct dependency version in pom.xml.
# Used when vulnerable dependency is directly mentioned in pom.xml.

def update_direct_dependency(repo_path: str, group_id: str, artifact_id: str, new_version: str) -> str:
    """Updates version of a direct dependency in pom.xml"""
    pom_path = os.path.join(repo_path, "pom.xml")
    ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
    ns = {"maven": "http://maven.apache.org/POM/4.0.0"}
    tree = ET.parse(pom_path)
    root = tree.getroot()

    for dep in root.findall(".//maven:dependency", ns):
        artifact = dep.find("maven:artifactId", ns)
        group = dep.find("maven:groupId", ns)
        version = dep.find("maven:version", ns)

        if (artifact is not None and artifact.text == artifact_id and
                group is not None and group.text == group_id):
            if version is not None:
                old_version = version.text
                version.text = new_version
                tree.write(pom_path, encoding="utf-8", xml_declaration=True)
                print(f"[DepUpdater] {artifact_id}: {old_version} -> {new_version}")
                return f"Updated {artifact_id} from {old_version} to {new_version}"
            else:
                return f"Error: {artifact_id} has no version tag in pom.xml"

    return f"Error: {artifact_id} not found in pom.xml"