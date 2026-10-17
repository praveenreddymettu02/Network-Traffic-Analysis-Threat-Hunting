"""
MITRE ATT&CK Framework Mapping Configuration

Centralized mapping module connecting real detection engine alert types
to official MITRE ATT&CK Tactics, Techniques, and IDs.
"""

from typing import Dict, Any, Optional

MITRE_MAPPINGS: Dict[str, Dict[str, str]] = {
    "PORT_SCAN": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "mapping_status": "Potential / Suspected",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts."
    },
    "DNS_FLOOD": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "tactic": "Impact",
        "mapping_status": "Potential / Suspected",
        "description": "Adversaries may perform Network Denial of Service attacks to degrade or disrupt DNS services."
    },
    "ICMP_FLOOD": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "mapping_status": "Potential / Suspected",
        "description": "Adversaries may conduct network flood attacks using ICMP packets to consume network bandwidth."
    },
    "EXCESSIVE_TCP": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "mapping_status": "Potential / Suspected",
        "description": "Adversaries may target endpoints with high-volume TCP connection attempts to exhaust server resources."
    },
    "BEACONING": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "mapping_status": "Potential / Suspected",
        "description": "Adversaries may communicate using application layer protocols (HTTP/HTTPS) with regular time intervals to avoid detection."
    },
    "BRUTE_FORCE": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "mapping_status": "Potential / Suspected",
        "description": "Adversaries may use brute force techniques to gain access to accounts by systematically guessing passwords or credentials."
    }
}


def get_mitre_mapping(detection_type: str) -> Optional[Dict[str, str]]:
    """
    Retrieve MITRE ATT&CK mapping for a given detection type.
    Normalizes detection type string to uppercase.
    """
    if not detection_type:
        return None
    normalized_type = str(detection_type).strip().upper().replace('-', '_')
    return MITRE_MAPPINGS.get(normalized_type)


def get_all_mitre_mappings() -> Dict[str, Dict[str, str]]:
    """Return all defined MITRE ATT&CK mappings."""
    return MITRE_MAPPINGS
