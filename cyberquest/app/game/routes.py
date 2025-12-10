# app/game/routes.py

from flask import render_template, request, redirect, url_for
from . import game_bp
from .state import load_state, save_state, reset_state
from .engine import GameEngine
from . import events
from .reference_data import APPROVED_USERS, APPROVED_DEVICES


@game_bp.route("/reset")
def reset():
    """
    Clear the current game state and start a new shift.
    """
    reset_state()
    return redirect(url_for("game.dashboard"))


@game_bp.route("/", methods=["GET"])
def dashboard():
    """
    Main game view. Shows the current event inside the SOC monitor.
    If the game is over, shows the Game Over screen.
    If a new day (level) has just started, shows the 'Welcome to Day X' popup.
    """
    state = load_state()

    # If the player has already been fired, go straight to game over.
    if state.is_over:
        save_state(state)
        return render_template(
            "game/game_over.html",
            state=state,
            approved_users=APPROVED_USERS,
            approved_devices=APPROVED_DEVICES,
        )

    # If we have a pending day popup, show it before generating events.
    if state.pending_day_popup:
        save_state(state)
        return render_template(
            "game/day_popup.html",
            state=state,
            approved_users=APPROVED_USERS,
            approved_devices=APPROVED_DEVICES,
        )

    engine = GameEngine(state)

    # If there's a current intrusion event, check if it has timed out.
    if state.current_event and state.current_event.get("type") == events.EVENT_INTRUSION:
        engine.check_intrusion_timeout()
        if state.is_over:
            save_state(state)
            return render_template(
                "game/game_over.html",
                state=state,
                approved_users=APPROVED_USERS,
                approved_devices=APPROVED_DEVICES,
            )

    # If there is no current event, generate the next one.
    if not state.current_event:
        engine.next_event()

    save_state(state)

    ev = state.current_event

    # Safety check: if for some reason we still don't have an event,
    # just show a blank dashboard.
    if not ev:
        return render_template(
            "game/dashboard.html",
            state=state,
            event=None,
            approved_users=APPROVED_USERS,
            approved_devices=APPROVED_DEVICES,
        )

    template_map = {
        events.EVENT_LOGIN: "game/event_login.html",
        events.EVENT_INTRUSION: "game/event_intrusion.html",
        events.EVENT_ROGUE_DEVICE: "game/event_rogue_device.html",
        events.EVENT_PHISHING: "game/event_phishing.html",
        events.EVENT_PATCH: "game/event_patch.html",
        events.EVENT_TOPOLOGY: "game/event_topology.html",
    }

    template = template_map.get(ev.get("type"), "game/dashboard.html")

    return render_template(
        template,
        state=state,
        event=ev,
        approved_users=APPROVED_USERS,
        approved_devices=APPROVED_DEVICES,
    )


@game_bp.route("/choice", methods=["POST"])
def choice():
    """
    Receive the player's decision for the current event (login/intrusion/
    rogue device/phishing/patch/topology), apply the game logic,
    then redirect back to the dashboard.
    """
    state = load_state()

    # If game already over, just go back to dashboard to show Game Over.
    if state.is_over:
        return redirect(url_for("game.dashboard"))

    engine = GameEngine(state)
    choice_value = request.form.get("choice")

    ev = state.current_event
    if not ev:
        # No current event; just refresh.
        return redirect(url_for("game.dashboard"))

    ev_type = ev.get("type")

    if ev_type == events.EVENT_LOGIN:
        engine.handle_login_choice(choice_value)
    elif ev_type == events.EVENT_INTRUSION:
        engine.handle_intrusion_choice(choice_value)
    elif ev_type == events.EVENT_ROGUE_DEVICE:
        engine.handle_rogue_device_choice(choice_value)
    elif ev_type == events.EVENT_PHISHING:
        engine.handle_phishing_choice(choice_value)
    elif ev_type == events.EVENT_PATCH:
        engine.handle_patch_choice(choice_value)
    elif ev_type == events.EVENT_TOPOLOGY:
        # topology sends JSON of connections via hidden field
        connections_json = request.form.get("connections")
        engine.handle_topology_choice(connections_json)

    save_state(state)

    return redirect(url_for("game.dashboard"))


@game_bp.route("/day_continue", methods=["POST"])
def day_continue():
    """
    Called when the player dismisses the 'Welcome to Day X' popup.
    Clears the pending_day_popup flag and returns to the dashboard.
    """
    state = load_state()
    state.pending_day_popup = False
    save_state(state)
    return redirect(url_for("game.dashboard"))
