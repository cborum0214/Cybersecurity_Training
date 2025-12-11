# app/game/events.py

import random
import time
from .reference_data import APPROVED_DEVICES

# Event type constants
EVENT_LOGIN = "login"
EVENT_INTRUSION = "intrusion"
EVENT_ROGUE_DEVICE = "rogue_device"
EVENT_PHISHING = "phishing"
EVENT_PATCH = "patch"
EVENT_TOPOLOGY = "topology"
EVENT_PACKET = "packet"
EVENT_FIREWALL = "firewall"
EVENT_SOCIAL = "social"
EVENT_PHYSICAL = "physical"
EVENT_PATH = "path"


# ---- Basic Events ----

def generate_login_event():
    """
    Simulate a login attempt event with clues for legitimacy.
    """
    users = [
        {"username": "j.smith", "role": "Nurse", "home_network": "SECURED"},
        {"username": "m.lee", "role": "Doctor", "home_network": "SECURED"},
        {"username": "a.jones", "role": "IT Admin", "home_network": "SECURED"},
        {"username": "visitor", "role": "Guest", "home_network": "GUEST"},
    ]

    user = random.choice(users)

    # Legit vs attacker
    is_legit = random.choice([True, True, False])

    if is_legit:
        source_ip = f"10.0.{random.randint(1, 20)}.{random.randint(10, 250)}"
        network = user["home_network"]
        failed_attempts = random.choice([0, 1])
    else:
        source_ip = f"203.0.113.{random.randint(10, 250)}"
        network = random.choice(["GUEST", "SECURED"])
        failed_attempts = random.choice([3, 5, 8])

    return {
        "id": f"login-{int(time.time()*1000)}",
        "type": EVENT_LOGIN,
        "username": user["username"],
        "role": user["role"],
        "source_ip": source_ip,
        "network": network,
        "failed_attempts": failed_attempts,
        "is_legitimate": is_legit,
        "description": "New login attempt detected.",
    }


def generate_intrusion_event():
    """
    IDS alert with built-in clues for real vs false positive.
    """
    scenarios = [
        # --- REAL ATTACKS ---
        {
            "source_device": "Radiology-WS-245",
            "target": "Patient Records Server",
            "detail": "Unusual data transfer volume to external IP",
            "severity": "Critical",
            "hint": "Large data exfiltration from a workstation to the internet.",
            "attack_real": True,
        },
        {
            "source_device": "NurseStation-3F-02",
            "target": "Medication Database",
            "detail": "Suspicious SQL queries using admin account at 02:13 AM",
            "severity": "High",
            "hint": "After-hours admin queries from a nurse station.",
            "attack_real": True,
        },
        {
            "source_device": "Pharmacy-Term-01",
            "target": "Patient Records Server",
            "detail": "Brute-force login attempts from single host",
            "severity": "High",
            "hint": "Repeated failed authentication attempts.",
            "attack_real": True,
        },

        # --- FALSE POSITIVES / BENIGN ---
        {
            "source_device": "VulnScanner-01",
            "target": "All Servers",
            "detail": "Port scan from internal vulnerability scanner",
            "severity": "Medium",
            "hint": "Known internal security tool performing scheduled scan.",
            "attack_real": False,
        },
        {
            "source_device": "BackupServer-01",
            "target": "Patient Records Server",
            "detail": "High data transfer volume to backup repository",
            "severity": "Low",
            "hint": "Scheduled backup job running during maintenance window.",
            "attack_real": False,
        },
        {
            "source_device": "ITAdmin-Desktop-01",
            "target": "Domain Controller",
            "detail": "Kerberos authentication spikes during patch rollout",
            "severity": "Medium",
            "hint": "Activity coincides with documented maintenance.",
            "attack_real": False,
        },
    ]

    s = random.choice(scenarios)
    return {
        "id": f"intrusion-{int(time.time()*1000)}",
        "type": EVENT_INTRUSION,
        "source_device": s["source_device"],
        "target": s["target"],
        "detail": s["detail"],
        "severity": s["severity"],
        "hint": s["hint"],
        "attack_real": s["attack_real"],
        "description": "Intrusion detection system reports suspicious access.",
        "timeout_seconds": 30,
    }


def generate_rogue_device_event():
    """
    Rogue device scenario tied to APPROVED_DEVICES.

    - If legitimate: use a device from APPROVED_DEVICES.
    - If malicious: generate a random MAC not in APPROVED_DEVICES.
    """
    legit = random.choice([True, False, False])  # skew toward malicious

    if legit and APPROVED_DEVICES:
        dev = random.choice(APPROVED_DEVICES)
        mac = dev["mac"]
        manufacturer = dev.get("manufacturer", "Known Vendor")
        location = dev.get("location", "Documented Location")
        malicious = False
    else:
        # set of approved MACs
        approved_macs = {d["mac"] for d in APPROVED_DEVICES}

        # Generate MAC not in approved list
        while True:
            mac_candidate = "A4:35:EF:{:02X}:{:02X}:{:02X}".format(
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
            )
            if mac_candidate not in approved_macs:
                mac = mac_candidate
                break

        manufacturer = random.choice(
            ["Raspberry Pi Foundation", "Unknown Vendor", "No-Name Switch Co."]
        )
        location = random.choice(
            [
                "3rd Floor Nurse’s Station",
                "OR Wing",
                "Main Lobby Closet",
                "ICU Hallway",
            ]
        )
        malicious = True

    return {
        "id": f"rogue-{int(time.time()*1000)}",
        "type": EVENT_ROGUE_DEVICE,
        "mac_address": mac,
        "manufacturer": manufacturer,
        "location": location,
        "malicious": malicious,
        "description": "New device detected on the secured network.",
    }


def generate_phishing_event():
    """
    Phishing email classification event.
    """
    scenarios = [
        {
            "sender_email": "it-support@riverbend-hospital.org",
            "subject": "Password expiry notification",
            "link_domain": "portal.riverbend-hospital.org",
            "is_phishing": False,
        },
        {
            "sender_email": "it-support@riverbend-h0spital.org",
            "subject": "URGENT: Password Reset Required",
            "link_domain": "riverbend-support.com",
            "is_phishing": True,
        },
        {
            "sender_email": "hr@riverbend-hospital.org",
            "subject": "Updated benefits portal",
            "link_domain": "benefits.riverbend-hospital.org",
            "is_phishing": False,
        },
        {
            "sender_email": "hr@riverbend-hosp1tal.com",
            "subject": "Important payroll update",
            "link_domain": "secure-payroll-update.com",
            "is_phishing": True,
        },
    ]

    s = random.choice(scenarios)
    return {
        "id": f"phishing-{int(time.time()*1000)}",
        "type": EVENT_PHISHING,
        "sender_email": s["sender_email"],
        "subject": s["subject"],
        "link_domain": s["link_domain"],
        "is_phishing": s["is_phishing"],
        "description": "Email flagged for phishing triage.",
    }


def generate_patch_event():
    """
    Patch management scenario.
    """
    systems = [
        "EHR Application Server",
        "Medication Database Server",
        "Radiology Image Archive",
        "Nurse Station Terminals",
    ]
    severities = ["Critical", "High", "Medium"]
    loads = ["normal hours", "night shift", "maintenance window"]

    system = random.choice(systems)
    severity = random.choice(severities)
    business_load = random.choice(loads)
    exploit_in_wild = random.choice([True, False, False])  # more often False

    return {
        "id": f"patch-{int(time.time()*1000)}",
        "type": EVENT_PATCH,
        "system": system,
        "severity": severity,
        "business_load": business_load,
        "exploit_in_wild": exploit_in_wild,
        "description": "New security patch is available.",
    }


def generate_topology_event():
    """
    Level 3 topology builder.
    """
    return {
        "id": f"topology-{int(time.time()*1000)}",
        "type": EVENT_TOPOLOGY,
        "description": (
            "Drag devices and create connections to match the hospital network "
            "diagram: Internet → External Firewall → Router 1 → Switch 1 (DMZ) → "
            "Internal Firewall → Router 2 → Switch 2 → Internal Server and users, "
            "with a Web Server off Switch 1."
        ),
    }


# ---- Advanced Events (Levels 4–8) ----

def generate_packet_event():
    """
    Packet inspection scenario: decide allow / drop / investigate.
    """
    scenarios = [
        # Real malicious
        {
            "src_ip": "10.15.3.42",
            "dst_ip": "185.23.90.12",
            "src_port": 51023,
            "dst_port": 4444,
            "protocol": "TCP",
            "flags": "SYN",
            "payload": "encrypted C2 beacon",
            "description": "Outbound connection from internal workstation to suspicious external host.",
            "correct_action": "drop",
            "explanation": "Outbound C2-style traffic to unknown external IP on uncommon port.",
        },
        {
            "src_ip": "10.2.5.18",
            "dst_ip": "10.99.0.5",
            "src_port": 53211,
            "dst_port": 1433,
            "protocol": "TCP",
            "flags": "PSH,ACK",
            "payload": "SELECT * FROM Patients WHERE id='1' OR '1'='1'--",
            "description": "Internal host sending suspicious SQL payload to database server.",
            "correct_action": "drop",
            "explanation": "SQL injection payload targeting patient database.",
        },
        # Benign
        {
            "src_ip": "10.1.10.5",
            "dst_ip": "8.8.8.8",
            "src_port": 51000,
            "dst_port": 53,
            "protocol": "UDP",
            "flags": "",
            "payload": "DNS query: api.riverbend-hospital.org",
            "description": "DNS lookup from internal app server.",
            "correct_action": "allow",
            "explanation": "Standard DNS query to well-known resolver.",
        },
        {
            "src_ip": "10.10.3.15",
            "dst_ip": "52.22.10.44",
            "src_port": 52111,
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "ESTABLISHED",
            "payload": "TLS encrypted application traffic",
            "description": "HTTPS session to approved cloud EHR provider.",
            "correct_action": "allow",
            "explanation": "Approved HTTPS traffic to known provider.",
        },
        # Suspicious / Investigate
        {
            "src_ip": "10.3.40.7",
            "dst_ip": "198.51.100.77",
            "src_port": 51234,
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "PSH,ACK",
            "payload": "Base64 blob, user-agent: curl/7.29",
            "description": "Repeated HTTP posts from radiology workstation to unknown host.",
            "correct_action": "investigate",
            "explanation": "Pattern is suspicious but not enough to outright drop without impact analysis.",
        },
    ]
    s = random.choice(scenarios)
    s.update({
        "id": f"packet-{int(time.time()*1000)}",
        "type": EVENT_PACKET,
    })
    return s


def generate_firewall_event():
    """
    Firewall rule scenario: student must craft an allow/deny rule.
    """
    scenarios = [
        {
            "id": f"fw-{int(time.time()*1000)}",
            "type": EVENT_FIREWALL,
            "description": "Allow clinicians to access the hospital web portal over HTTPS from the internal network.",
            "prompt": "Create a rule that allows HTTPS traffic from internal subnet 10.0.0.0/16 to the Web Portal server at 10.20.0.10.",
            "expected_action": "allow",
            "expected_protocol": "tcp",
            "expected_port": "443",
        },
        {
            "id": f"fw-{int(time.time()*1000)}",
            "type": EVENT_FIREWALL,
            "description": "Block RDP access from the internet to internal servers.",
            "prompt": "Create a rule that blocks inbound RDP from any external IP to internal subnet 10.0.0.0/16.",
            "expected_action": "deny",
            "expected_protocol": "tcp",
            "expected_port": "3389",
        },
    ]
    return random.choice(scenarios)


def generate_social_event():
    """
    Social engineering scenario.
    """
    scenarios = [
        {
            "id": f"social-{int(time.time()*1000)}",
            "type": EVENT_SOCIAL,
            "channel": "Email",
            "sender": "ceo@riverbend-h0spital.org",
            "content": "I need you to send me the latest payroll file immediately. Do not tell anyone about this.",
            "hint": "Sender address slightly misspelled, urgent secrecy.",
            "correct_action": "verify",
            "description": "Suspicious request for sensitive data.",
        },
        {
            "id": f"social-{int(time.time()*1000)}",
            "type": EVENT_SOCIAL,
            "channel": "Phone",
            "sender": "Helpdesk Impersonator",
            "content": "This is IT. I need your password to fix your email.",
            "hint": "Policy: IT will never ask for passwords.",
            "correct_action": "escalate",
            "description": "Phone call asking user for password.",
        },
        {
            "id": f"social-{int(time.time()*1000)}",
            "type": EVENT_SOCIAL,
            "channel": "Chat",
            "sender": "Nurse Kelly",
            "content": "Hey, system is down. Can you approve my account reset? Ticket #1234.",
            "hint": "Message references valid ticket, from known user.",
            "correct_action": "verify",
            "description": "Legitimate-appearing support request.",
        },
    ]
    return random.choice(scenarios)


def generate_physical_event():
    """
    Physical security / camera feed scenario.
    """
    scenarios = [
        {
            "id": f"phys-{int(time.time()*1000)}",
            "type": EVENT_PHYSICAL,
            "location": "Server Room Door",
            "description": "Camera shows an unknown person tailgating behind an employee into the server room.",
            "hint": "Tailgating into restricted area.",
            "correct_action": "respond",
        },
        {
            "id": f"phys-{int(time.time()*1000)}",
            "type": EVENT_PHYSICAL,
            "location": "Main Lobby",
            "description": "Delivery person leaves a USB drive on the front desk.",
            "hint": "Unattended unknown USB in public area.",
            "correct_action": "respond",
        },
        {
            "id": f"phys-{int(time.time()*1000)}",
            "type": EVENT_PHYSICAL,
            "location": "Nurse Station",
            "description": "Employee briefly walks away, but their screen locks automatically.",
            "hint": "Security control is working as intended.",
            "correct_action": "log",
        },
        {
            "id": f"phys-{int(time.time()*1000)}",
            "type": EVENT_PHYSICAL,
            "location": "Staff Entrance",
            "description": "Badge reader denies access and the person walks away.",
            "hint": "No sign of forced entry.",
            "correct_action": "ignore",
        },
    ]
    return random.choice(scenarios)


def generate_path_event():
    """
    Advanced attack path scenario.
    """
    scenarios = [
        {
            "id": f"path-{int(time.time()*1000)}",
            "type": EVENT_PATH,
            "description": (
                "An attacker compromises a lobby kiosk, then uses it to pivot into "
                "the internal network and reach the Medication Database."
            ),
            "steps": [
                "Lobby Kiosk (public)",
                "Internal Network",
                "Medication Database Server",
            ],
            "question": "Where is the best place to enforce strong network segmentation?",
            "choices": [
                "Between kiosk and internal network",
                "At database only",
                "At internet edge",
            ],
            "correct_action": "segment_kiosk",
        },
        {
            "id": f"path-{int(time.time()*1000)}",
            "type": EVENT_PATH,
            "description": (
                "Phishing email compromises a doctor's laptop, which is then "
                "used to access the EMR server."
            ),
            "steps": [
                "Doctor's Laptop",
                "Internal Network",
                "EMR Server",
            ],
            "question": "What is the most effective control to break this path?",
            "choices": [
                "Endpoint EDR on laptops",
                "Extra firewall at internet edge",
                "More backups",
            ],
            "correct_action": "endpoint_edr",
        },
    ]
    return random.choice(scenarios)


# ---- Level-aware random event picker ----

def random_event(level: int = 1):
    """
    Choose a random event type, with more advanced events unlocked at higher levels.
    Topology is injected separately by the engine at level 3.
    """
    base_types = [EVENT_LOGIN, EVENT_INTRUSION, EVENT_ROGUE_DEVICE, EVENT_PHISHING, EVENT_PATCH]
    weights = [0.40, 0.15, 0.15, 0.15, 0.15]

    # Level 4+: unlock packet inspection
    if level >= 4:
        base_types.append(EVENT_PACKET)
        weights.append(0.10)

    # Level 5+: firewall rule
    if level >= 5:
        base_types.append(EVENT_FIREWALL)
        weights.append(0.08)

    # Level 6+: social engineering
    if level >= 6:
        base_types.append(EVENT_SOCIAL)
        weights.append(0.08)

    # Level 7+: physical security
    if level >= 7:
        base_types.append(EVENT_PHYSICAL)
        weights.append(0.08)

    # Level 8+: attack path analysis
    if level >= 8:
        base_types.append(EVENT_PATH)
        weights.append(0.06)

    event_type = random.choices(population=base_types, weights=weights, k=1)[0]

    if event_type == EVENT_LOGIN:
        return generate_login_event()
    elif event_type == EVENT_INTRUSION:
        return generate_intrusion_event()
    elif event_type == EVENT_ROGUE_DEVICE:
        return generate_rogue_device_event()
    elif event_type == EVENT_PHISHING:
        return generate_phishing_event()
    elif event_type == EVENT_PATCH:
        return generate_patch_event()
    elif event_type == EVENT_PACKET:
        return generate_packet_event()
    elif event_type == EVENT_FIREWALL:
        return generate_firewall_event()
    elif event_type == EVENT_SOCIAL:
        return generate_social_event()
    elif event_type == EVENT_PHYSICAL:
        return generate_physical_event()
    elif event_type == EVENT_PATH:
        return generate_path_event()
