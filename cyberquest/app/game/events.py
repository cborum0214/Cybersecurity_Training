# app/game/events.py

import random
import time

# Event type constants
EVENT_LOGIN = "login"
EVENT_INTRUSION = "intrusion"
EVENT_ROGUE_DEVICE = "rogue_device"
EVENT_PHISHING = "phishing"
EVENT_PATCH = "patch"
EVENT_TOPOLOGY = "topology"


def generate_login_event():
    legit = random.choice([True, False])

    if legit:
        username = random.choice(["dr_smith", "nurse_lee", "tech_jones", "dr_patel"])
        source_ip = "10.{}.{}.{}".format(
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(1, 254),
        )
        network = "secured"
        failed_attempts = random.randint(0, 2)
    else:
        username = random.choice(["admin", "dr_smith", "root", "backup", "it_support"])
        source_ip = "{}.{}.{}.{}".format(
            random.randint(20, 200),
            random.randint(20, 200),
            random.randint(0, 255),
            random.randint(1, 254),
        )
        network = random.choice(["guest", "external"])
        failed_attempts = random.randint(3, 10)

    return {
        "id": f"login-{int(time.time()*1000)}",
        "type": EVENT_LOGIN,
        "username": username,
        "source_ip": source_ip,
        "network": network,
        "failed_attempts": failed_attempts,
        "is_legitimate": legit,
        "description": "Login attempt detected in the hospital auth logs.",
    }


def generate_intrusion_event():
    """
    Generate an IDS alert with built-in clues so students can reason about
    whether it's a real attack or a false positive.
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

    scenario = random.choice(scenarios)

    return {
        "id": f"intrusion-{int(time.time()*1000)}",
        "type": EVENT_INTRUSION,
        "source_device": scenario["source_device"],
        "target": scenario["target"],
        "detail": scenario["detail"],
        "severity": scenario["severity"],
        "hint": scenario["hint"],
        "attack_real": scenario["attack_real"],
        "description": "Intrusion detection system reports suspicious access.",
        "timeout_seconds": 30,
    }



def generate_rogue_device_event():
    malicious = random.choice([True, False])

    return {
        "id": f"rogue-{int(time.time()*1000)}",
        "type": EVENT_ROGUE_DEVICE,
        "mac_address": "A4:35:EF:{:02X}:{:02X}:{:02X}".format(
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
        ),
        "manufacturer": random.choice(
            ["Raspberry Pi Foundation", "Dell", "HP", "Unknown Vendor"]
        ),
        "location": random.choice(
            [
                "3rd Floor Nurse’s Station",
                "OR Wing",
                "Main Lobby Closet",
                "ICU Hallway",
            ]
        ),
        "malicious": malicious,
        "description": "New device detected on the secured network.",
    }


# --- NEW SCENARIOS ---


def generate_phishing_event():
    """
    Generate a phishing email triage scenario.
    """
    is_phishing = random.choice([True, False, True])  # skewed toward phishing

    legit_sender = random.choice(
        [
            ("HR Department", "hr@riverbend-hospital.org"),
            ("IT Support", "itsupport@riverbend-hospital.org"),
            ("Benefits Office", "benefits@riverbend-hospital.org"),
        ]
    )
    fake_domain = random.choice(
        [
            "riverbend-hospital-security.com",
            "riverbend-benefits-support.com",
            "secure-riverbend-login.net",
        ]
    )

    if is_phishing:
        display_name, real_email = legit_sender
        # subtle or obvious mismatches
        sender_email = random.choice(
            [
                f"{display_name.replace(' ', '').lower()}@{fake_domain}",
                f"no-reply@{fake_domain}",
                f"security-alert@{fake_domain}",
            ]
        )
        subject = random.choice(
            [
                "URGENT: Password Expiring Today – Action Required",
                "Important Benefits Update – Log In Immediately",
                "Security Notice: Suspicious Activity Detected",
            ]
        )
        body_preview = random.choice(
            [
                "Dear employee, your account will be disabled unless you verify...",
                "We noticed unusual login attempts. Please confirm your identity...",
                "You have an outstanding benefits payment. Log in to prevent loss...",
            ]
        )
        link_domain = fake_domain
    else:
        display_name, sender_email = legit_sender
        subject = random.choice(
            [
                "Reminder: Annual Security Training",
                "Benefits Enrollment Window Opens Next Week",
                "Scheduled Maintenance Notice",
            ]
        )
        body_preview = random.choice(
            [
                "Please complete your required training by the end of the month.",
                "Enrollment for health and dental benefits will begin on...",
                "This is a reminder of scheduled downtime for minor maintenance...",
            ]
        )
        link_domain = "riverbend-hospital.org"

    return {
        "id": f"phishing-{int(time.time()*1000)}",
        "type": EVENT_PHISHING,
        "display_name": display_name,
        "sender_email": sender_email,
        "subject": subject,
        "body_preview": body_preview,
        "link_domain": link_domain,
        "is_phishing": is_phishing,
        "description": "New email flagged by the secure email gateway for review.",
    }


def generate_patch_event():
    """
    Generate a patch management decision scenario.
    """
    # Is this a vulnerability currently being exploited in the wild?
    exploit_in_wild = random.choice([True, False])
    severity = random.choice(["High", "Critical"])
    system = random.choice(
        ["EMR Server Cluster", "Medication Dispensing System", "Radiology PACS"]
    )
    business_load = random.choice(
        ["Low", "Moderate", "High (surgeries in progress)"]
    )

    return {
        "id": f"patch-{int(time.time()*1000)}",
        "type": EVENT_PATCH,
        "severity": severity,
        "system": system,
        "business_load": business_load,
        "exploit_in_wild": exploit_in_wild,
        "description": "New security patch is available. Operations may be impacted.",
    }


def random_event():
    """
    Choose a random event type with weights to control frequency.
    """
    event_type = random.choices(
        population=[
            EVENT_LOGIN,
            EVENT_INTRUSION,
            EVENT_ROGUE_DEVICE,
            EVENT_PHISHING,
            EVENT_PATCH,
        ],
        weights=[0.45, 0.15, 0.15, 0.15, 0.10],
        k=1,
    )[0]

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
    
def generate_topology_event():
    """
    Network build challenge: students must connect the devices to match
    the reference diagram.
    """
    return {
        "id": f"topology-{int(time.time()*1000)}",
        "type": EVENT_TOPOLOGY,
        "description": (
            "Drag the devices into place and connect them to match the "
            "hospital network diagram: Internet → External Firewall → Router 1 → "
            "Switch 1 (DMZ) → Internal Firewall → Router 2 → Switch 2 → "
            "Internal Server and User PCs, with a Web Server off Switch 1."
        ),
    }

