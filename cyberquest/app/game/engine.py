# app/game/engine.py

import time
import json
from .state import GameState
from . import events


class GameEngine:
    """
    Contains the core game logic. Operates on a GameState instance.
    """

    def __init__(self, state: GameState):
        self.state = state

    # --- Internal helper ---

    def _register_correct_decision(self):
        """
        Called whenever the player makes a correct decision.
        After 10 correct decisions, the shift ends:
        - Reprimands reset to 0
        - correct_decisions_in_shift resets to 0
        - Level is advanced
        """
        self.state.correct_decisions_in_shift += 1
        remaining = 10 - self.state.correct_decisions_in_shift

        if remaining > 0:
            self.state.add_log(
                f"[SYSTEM] Correct decision. {remaining} more to complete this shift."
            )
            return

        # Shift complete
        self.state.add_log(
            "[SYSTEM] Shift complete. You made 10 correct decisions. "
            "Your shift has ended."
        )

        # Advance level, reset reprimands, reset counter
        self.state.level += 1
        self.state.reprimands = 0
        self.state.correct_decisions_in_shift = 0

        # Trigger day popup
        self.state.pending_day_popup = True

        self.state.add_log(
            f"[SYSTEM] Shift complete. Now starting Day {self.state.level}."
        )

    # --- Event lifecycle ---

    def next_event(self):
        """
        Generate a new event and attach it to the state.
        Also logs a summary of the event.
        """

        # Special rule: once the player reaches level 3, and they have not yet
        # completed the topology challenge, force the topology event.
        if self.state.level >= 3 and not self.state.topology_completed:
            ev = events.generate_topology_event()
        else:
            ev = events.random_event()

        self.state.current_event = ev

        # Timed intrusion events
        if ev["type"] == events.EVENT_INTRUSION:
            now = time.time()
            self.state.current_event_started_at = now
            self.state.current_event_deadline = now + ev["timeout_seconds"]
            self.state.add_log(
                f"[ALERT] Intrusion detection: {ev['source_device']} → "
                f"{ev['target']} ({ev['detail']})"
            )

        # Login events
        elif ev["type"] == events.EVENT_LOGIN:
            self.state.current_event_started_at = None
            self.state.current_event_deadline = None
            self.state.add_log(
                f"[AUTH] Login attempt: user={ev['username']} "
                f"ip={ev['source_ip']} net={ev['network']} "
                f"failed={ev['failed_attempts']}"
            )

        # Rogue device events
        elif ev["type"] == events.EVENT_ROGUE_DEVICE:
            self.state.current_event_started_at = None
            self.state.current_event_deadline = None
            self.state.add_log(
                f"[NETWORK] New device detected: MAC={ev['mac_address']} "
                f"vendor={ev['manufacturer']} loc={ev['location']}"
            )

        # Phishing events
        elif ev["type"] == events.EVENT_PHISHING:
            self.state.current_event_started_at = None
            self.state.current_event_deadline = None
            self.state.add_log(
                f"[EMAIL] Email triage: from={ev['sender_email']} "
                f"subject=\"{ev['subject']}\" domain={ev['link_domain']}"
            )

        # Patch events
        elif ev["type"] == events.EVENT_PATCH:
            self.state.current_event_started_at = None
            self.state.current_event_deadline = None
            self.state.add_log(
                f"[PATCH] New {ev['severity']} patch for {ev['system']} "
                f"(load={ev['business_load']})"
            )

        #Topology events
        elif ev["type"] == events.EVENT_TOPOLOGY:
            self.state.current_event_started_at = None
            self.state.current_event_deadline = None
            self.state.add_log(
                "[TRAINING] Topology challenge: design the hospital network."
            )

        return ev

    # --- Decision handlers ---

    def handle_login_choice(self, choice: str):
        """
        Handle player decision for a login event.

        choice: 'allow' or 'deny'
        """
        ev = self.state.current_event
        if not ev or ev["type"] != events.EVENT_LOGIN:
            return

        legit = ev["is_legitimate"]

        if choice == "allow":
            if legit:
                self.state.add_score(10)
                self.state.add_log(
                    f"[DECISION] ALLOW login for {ev['username']} "
                    f"from {ev['source_ip']} (legitimate)."
                )
                self._register_correct_decision()
            else:
                self.state.add_reprimand(
                    f"Allowed attacker login as {ev['username']} "
                    f"from {ev['source_ip']}."
                )

        elif choice == "deny":
            if legit:
                self.state.add_reprimand(
                    f"Blocked legitimate user {ev['username']} "
                    f"from {ev['source_ip']}."
                )
            else:
                self.state.add_score(10)
                self.state.add_log(
                    f"[DECISION] DENY login for {ev['username']} "
                    f"from {ev['source_ip']} (attack blocked)."
                )
                self._register_correct_decision()

        # Clear current event after decision
        self.state.current_event = None
        self.state.current_event_started_at = None
        self.state.current_event_deadline = None

    def handle_intrusion_choice(self, choice: str):
        """
        Handle player decision for an intrusion event.

        choice: 'shutdown' or 'ignore'
        """
        ev = self.state.current_event
        if not ev or ev["type"] != events.EVENT_INTRUSION:
            return

        real_attack = ev["attack_real"]

        if choice == "shutdown":
            if real_attack:
                self.state.add_score(20)
                self.state.add_log(
                    "[DECISION] SHUTDOWN secured network – real attack contained."
                )
                self._register_correct_decision()
            else:
                self.state.add_reprimand(
                    "Shut down secured network for a false alarm "
                    "(hospital operations disrupted)."
                )

        elif choice == "ignore":
            if real_attack:
                self.state.add_reprimand(
                    "Ignored real intrusion (patient data compromised)."
                )
            else:
                self.state.add_score(5)
                self.state.add_log(
                    "[DECISION] Ignored intrusion alert – IDS was correct "
                    "(no threat)."
                )
                self._register_correct_decision()

        # Clear current event after decision
        self.state.current_event = None
        self.state.current_event_started_at = None
        self.state.current_event_deadline = None

    def handle_rogue_device_choice(self, choice: str):
        """
        Handle player decision for a rogue device event.

        choice: 'disconnect' or 'allow'
        """
        ev = self.state.current_event
        if not ev or ev["type"] != events.EVENT_ROGUE_DEVICE:
            return

        malicious = ev["malicious"]

        if choice == "disconnect":
            if malicious:
                self.state.add_score(15)
                self.state.add_log(
                    f"[DECISION] DISCONNECT rogue device {ev['mac_address']} "
                    f"at {ev['location']} (malicious)."
                )
                self._register_correct_decision()
            else:
                self.state.add_reprimand(
                    f"Disconnected legitimate device {ev['mac_address']} "
                    f"at {ev['location']}."
                )

        elif choice == "allow":
            if malicious:
                self.state.add_reprimand(
                    f"Allowed rogue device {ev['mac_address']} to remain on "
                    "secured network."
                )
            else:
                self.state.add_score(5)
                self.state.add_log(
                    f"[DECISION] ALLOW device {ev['mac_address']} at "
                    f"{ev['location']} (benign)."
                )
                self._register_correct_decision()

        # Clear current event after decision
        self.state.current_event = None
        self.state.current_event_started_at = None
        self.state.current_event_deadline = None

    def handle_phishing_choice(self, choice: str):
        """
        Handle player decision for a phishing email event.

        choice: 'mark_phishing' or 'deliver'
        """
        ev = self.state.current_event
        if not ev or ev["type"] != events.EVENT_PHISHING:
            return

        is_phishing = ev["is_phishing"]

        if choice == "mark_phishing":
            if is_phishing:
                self.state.add_score(15)
                self.state.add_log(
                    f"[DECISION] Marked email from {ev['sender_email']} as phishing "
                    "(malicious email quarantined)."
                )
                self._register_correct_decision()
            else:
                self.state.add_reprimand(
                    f"Incorrectly flagged legitimate email from {ev['sender_email']} "
                    "as phishing (workflow disrupted)."
                )
        elif choice == "deliver":
            if is_phishing:
                self.state.add_reprimand(
                    f"Delivered phishing email from {ev['sender_email']} "
                    "(users exposed to malicious link)."
                )
            else:
                self.state.add_score(8)
                self.state.add_log(
                    f"[DECISION] Allowed legitimate email from {ev['sender_email']} "
                    "to be delivered."
                )
                self._register_correct_decision()

        self.state.current_event = None
        self.state.current_event_started_at = None
        self.state.current_event_deadline = None

    def handle_patch_choice(self, choice: str):
        """
        Handle player decision for a patch management event.

        choice: 'apply_now' or 'postpone'
        """
        ev = self.state.current_event
        if not ev or ev["type"] != events.EVENT_PATCH:
            return

        exploit_in_wild = ev["exploit_in_wild"]
        severity = ev["severity"]
        system = ev["system"]
        load = ev["business_load"]

        if choice == "apply_now":
            if exploit_in_wild:
                # Correct: patch immediately when active exploit exists
                self.state.add_score(20)
                self.state.add_log(
                    f"[DECISION] Applied {severity} patch on {system} "
                    "(known exploited vulnerability mitigated)."
                )
                self._register_correct_decision()
            else:
                # Unnecessary disruption
                self.state.add_reprimand(
                    f"Applied patch on {system} during {load}, causing unneeded "
                    "downtime and workflow disruption."
                )
        elif choice == "postpone":
            if exploit_in_wild:
                # Bad call: risk realized
                self.state.add_reprimand(
                    f"Postponed critical patch on {system} despite active exploits "
                    "in the wild (system compromised)."
                )
            else:
                # Reasonable decision: no exploit yet
                self.state.add_score(10)
                self.state.add_log(
                    f"[DECISION] Postponed patch on {system} during {load} "
                    "(no active exploits reported)."
                )
                self._register_correct_decision()

        self.state.current_event = None
        self.state.current_event_started_at = None
        self.state.current_event_deadline = None

    # --- Timers ---

    def check_intrusion_timeout(self):
        """
        If an intrusion event has a deadline and the current time is past it,
        auto-apply the 'ignore' decision.
        """
        ev = self.state.current_event
        if not ev or ev["type"] != events.EVENT_INTRUSION:
            return

        if self.state.current_event_deadline is None:
            return

        now = time.time()
        if now > self.state.current_event_deadline:
            self.state.add_log(
                "[TIMEOUT] Intrusion alert timer expired – no response "
                "received from operator."
            )
            # Auto-apply "ignore"
            self.handle_intrusion_choice("ignore")

    def handle_topology_choice(self, connections_json: str):
        """
        Handle the topology challenge submission.

        connections_json: JSON string of list of [from, to] pairs, e.g.
        [
          ["internet", "ext_fw"],
          ["ext_fw", "router1"],
          ...
        ]
        """

        ev = self.state.current_event
        if not ev or ev["type"] != events.EVENT_TOPOLOGY:
            return

        try:
            user_edges = json.loads(connections_json or "[]")
        except json.JSONDecodeError:
            user_edges = []

        # Canonical "correct" undirected edges for your diagram
        required_edges = {
            frozenset(("internet", "ext_fw")),
            frozenset(("ext_fw", "router1")),
            frozenset(("router1", "switch1")),
            frozenset(("switch1", "int_fw")),
            frozenset(("switch1", "web_server")),
            frozenset(("int_fw", "router2")),
            frozenset(("router2", "switch2")),
            frozenset(("switch2", "int_server")),
            frozenset(("switch2", "user1")),
            frozenset(("switch2", "user2")),
        }

        user_edge_set = set()
        for edge in user_edges:
            if not isinstance(edge, list) or len(edge) != 2:
                continue
            a, b = edge
            user_edge_set.add(frozenset((a, b)))

        if user_edge_set == required_edges:
            # Success!
            self.state.add_score(30)
            self.state.add_log(
                "[DECISION] Topology challenge solved correctly. "
                "Network diagram matches reference."
            )
            self.state.topology_completed = True
            self._register_correct_decision()
        else:
            # Incorrect topology
            self.state.add_reprimand(
                "Submitted incorrect network topology. Devices are not connected "
                "according to the design."
            )

        self.state.current_event = None
        self.state.current_event_started_at = None
        self.state.current_event_deadline = None

