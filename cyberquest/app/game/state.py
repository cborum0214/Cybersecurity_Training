from dataclasses import dataclass, field
from typing import Optional, Dict, List
import time
import uuid
from flask import session
import json

# Key used to store the game state in the Flask session
SESSION_KEY = "game_state"


@dataclass
class GameState:
    """
    Represents the current game session for a single player.
    Stored in the Flask session between requests.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    reprimands: int = 0
    score: int = 0
    is_over: bool = False

    # Level and shift tracking
    level: int = 1
    correct_decisions_in_shift: int = 0  # resets when shift ends
    pending_day_popup: bool = False      # show "Welcome to Day X" popup

    # Topology challenge tracking
    topology_completed: bool = False     # True once the level-3 network puzzle is solved

    # The current active event: login, intrusion, rogue device, phishing, patch, topology, etc.
    current_event: Optional[Dict] = None

    # For timed events (intrusion)
    current_event_started_at: Optional[float] = None
    current_event_deadline: Optional[float] = None

    # Running log messages displayed in the SOC terminal panel
    logs: List[str] = field(default_factory=list)

    # --- Convenience methods ---

    def add_reprimand(self, reason: str = ""):
        """
        Increment reprimands, log the reason, and check for game over.
        """
        self.reprimands += 1
        if reason:
            self.add_log(f"[REPRIMAND] {reason} (Total: {self.reprimands}/3)")
        else:
            self.add_log(f"[REPRIMAND] Policy violation (Total: {self.reprimands}/3)")

        if self.reprimands >= 3:
            self.is_over = True
            self.add_log("[SYSTEM] You have been terminated from your position.")

    def add_score(self, amount: int):
        """
        Increase the score by the given amount.
        """
        self.score += amount

    def add_log(self, message: str):
        """
        Append a log line with a timestamp, keeping only recent entries.
        """
        timestamp = time.strftime("%H:%M:%S")
        entry = f"{timestamp}  {message}"
        self.logs.append(entry)

        # Keep only the most recent 50 lines to avoid unbounded growth
        if len(self.logs) > 50:
            self.logs = self.logs[-50:]


# --- Session helpers ---


def save_state(state: GameState):
    """
    Serialize and save the GameState to the Flask session.
    """
    session[SESSION_KEY] = json.dumps(state.__dict__)


def load_state() -> GameState:
    """
    Load the GameState from the Flask session, or create a new one if none exists.
    """
    raw = session.get(SESSION_KEY)
    if not raw:
        # First-time or reset: start a new shift
        state = GameState()
        state.add_log("[SYSTEM] New shift started. Monitoring hospital network...")
        save_state(state)
        return state

    data = json.loads(raw)
    state = GameState()

    # Restore fields that exist in the saved data
    for k, v in data.items():
        setattr(state, k, v)

    # Ensure logs list exists (for older saved sessions)
    if not hasattr(state, "logs") or state.logs is None:
        state.logs = []
        state.add_log("[SYSTEM] Log system initialized.")

    # Ensure new fields exist for older sessions
    if not hasattr(state, "level") or state.level is None:
        state.level = 1
    if (not hasattr(state, "correct_decisions_in_shift") or
            state.correct_decisions_in_shift is None):
        state.correct_decisions_in_shift = 0
    if not hasattr(state, "pending_day_popup"):
        state.pending_day_popup = False
    if not hasattr(state, "topology_completed"):
        state.topology_completed = False

    return state


def reset_state():
    """
    Completely clear the current game state from the session.
    """
    if SESSION_KEY in session:
        session.pop(SESSION_KEY)
