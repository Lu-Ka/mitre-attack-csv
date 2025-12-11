#!/usr/local/bin/python3

import requests


# MITRE ATT&CK URL Data
URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

# Output folder
FOLDER = "output"
# Output files
FILE_TACTIC = "mitre_attack_tactic.csv"
FILE_TECHNIQUE = "mitre_attack_technique.csv"
FILE_TECHNIQUE_TACTIC = "mitre_attack_technique_tactic.csv"

TACTIC_NAME = {
    "collection": "Collection",
    "command-and-control": "CommandAndControl",
    "credential-access": "CredentialAccess",
    "defense-evasion": "DefenseEvasion",
    "discovery": "Discovery",
    "execution": "Execution",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "initial-access": "InitialAccess",
    "lateral-movement": "LateralMovement",
    "persistence": "Persistence",
    "privilege-escalation": "PrivilegeEscalation",
    "reconnaissance": "Reconnaissance",
    "resource-development": "ResourceDevelopment",
}


def getMitreAttackData():
    try:
        data = requests.get(URL)
    except Exception as e:
        print("[-] Error when downloading MITRE ATT&CK Data :")
        print(e)

        exit(1)

    return data.json()


def getTacticInfo(tactic):
    tactic_id = tactic["external_references"][0]["external_id"]
    tactic_name = tactic["name"]

    return {tactic_id: tactic_name}


class MitreTechniques:
    def __init__(self) -> None:
        self.techniques = {}
        self.techniques_tactics = {}
        self.failed_subtechniques = []

    def addTechnique(self, technique_id, name, parent_name=None):
        if parent_name:
            name = parent_name + ": " + name

        self.techniques[technique_id] = name

        return

    def addTactics(self, technique_id, tactics_info):
        tactics = [TACTIC_NAME[t["phase_name"]] for t in tactics_info]

        self.techniques_tactics[technique_id] = tactics

        return

    def getTechniqueInfo(self, technique):
        technique_id = technique["external_references"][0]["external_id"]
        name = technique["name"]
        tactics_info = technique["kill_chain_phases"]

        if technique["x_mitre_is_subtechnique"]:
            parent_id = technique_id.split(".")[0]

            if parent_id in self.techniques:
                parent_name = self.techniques[parent_id]
                self.addTechnique(technique_id, name, parent_name=parent_name)

            else:
                self.addTechnique(technique_id, name)
                self.failed_subtechniques.append(technique_id)

        else:
            self.addTechnique(technique_id, name)

        self.addTactics(technique_id, tactics_info)

        return

    def processFailedSubTechniques(self):
        for failed_subtechnique in self.failed_subtechniques:
            name = self.techniques[failed_subtechnique]

            parent_id = failed_subtechnique.split(".")[0]
            parent_name = self.techniques[parent_id]

            self.addTechnique(failed_subtechnique, name, parent_name=parent_name)

        return


if __name__ == "__main__":
    tactics = {}
    cls_technique = MitreTechniques()

    print("Downloading MITRE ATT&CK data...")
    mitre_attack_data = getMitreAttackData()
    print("[+] Mitre ATT&CK Data downloaded\n")

    print("Retrieving Tactics and Techniques data...")

    for element in mitre_attack_data["objects"]:
        mitre_type = element["type"]

        match mitre_type:
            case "x-mitre-tactic":
                tactic = getTacticInfo(element)
                tactics = tactics | tactic

            case "attack-pattern":
                cls_technique.getTechniqueInfo(element)

            case _:
                pass

    cls_technique.processFailedSubTechniques()
    techniques = cls_technique.techniques
    techniques_tactics = cls_technique.techniques_tactics

    print("[+] Tactics and Techniques retrieved\n")

    nb_tactics = len(tactics)
    nb_techniques = len(techniques)

    print(f"{nb_tactics} Tactiques - {nb_techniques} Techniques\n")

    print("Writing Tactic file...")

    filename_tactic = "./" + FOLDER + "/" + FILE_TACTIC
    with open(filename_tactic, "w") as f:
        f.write("id;name\n")
        for tactic in tactics:
            f.write(f"{tactic};{tactics[tactic]}\n")

    print("[+] Tactic file created\n")

    print("Writing Technique file...")

    filename_technique = "./" + FOLDER + "/" + FILE_TECHNIQUE
    with open(filename_technique, "w") as f:
        f.write("id;name\n")
        for technique in techniques:
            f.write(f"{technique};{techniques[technique]}\n")

    print("[+] Technique file created\n")

    print("Writing Technique / Tactics file...")

    filename_technique_tactic = "./" + FOLDER + "/" + FILE_TECHNIQUE_TACTIC
    with open(filename_technique_tactic, "w") as f:
        f.write("technique_id,tactics\n")
        for technique in techniques_tactics:
            tactics = "/".join(techniques_tactics[technique])
            f.write(f"{technique},{tactics}\n")

    print("[+] Technique / Tactics file created")

    exit()
