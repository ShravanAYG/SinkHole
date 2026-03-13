"""
Stage 2 Phase 2 — Advanced Behavioral Detection

This module implements deep behavioral analysis for post-gate detection:
- Mouse movement pattern analysis (jaggedness, straight lines, velocity)
- Keystroke dynamics (typing rhythm, Dwell time/Flight time)
- Scroll pattern analysis (velocity, acceleration, direction changes)
- Time-on-page vs content length analysis
- Click pattern analysis (click heatmap anomalies)
- Form interaction tracking
- Advanced trap mechanisms (honeypot fields, timing traps)
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Any

from .config import ScoringWeights


@dataclass(slots=True)
class BehavioralScoreOutcome:
    delta: float
    reasons: list[str]
    risk_flags: list[str]


class MousePatternAnalyzer:
    """Analyzes mouse movement patterns for bot detection."""

    @staticmethod
    def calculate_jaggedness(points: list[dict[str, float]]) -> float:
        """
        Calculate movement jaggedness (how "natural" the path is).
        Humans have slightly irregular, curved paths.
        Bots often have perfectly straight lines or overly smooth curves.
        adadwdwdawd
        Returns 0.0 for perfectly straight lines, higher for jagged paths.
        """
        if len(points) < 3:
            return 0.0

        angles: list[float] = []
        for i in range(1, len(points) - 1):
            p1 = (points[i-1]["x"], points[i-1]["y"])
            p2 = (points[i]["x"], points[i]["y"])
            p3 = (points[i+1]["x"], points[i+1]["y"])

            # Calculate angle at p2
            v1 = (p2[0] - p1[0], p2[1] - p1[1])
            v2 = (p3[0] - p2[0], p3[1] - p2[1])

            # Skip zero-length vectors
            if v1[0] == 0 and v1[1] == 0:
                continue
            if v2[0] == 0 and v2[1] == 0:
                continue

            # Calculate angle between vectors
            dot = v1[0] * v2[0] + v1[1] * v2[1]
            mag1 = math.sqrt(v1[0]**2 + v1[1]**2)
            mag2 = math.sqrt(v2[0]**2 + v2[1]**2)

            if mag1 == 0 or mag2 == 0:
                continue

            cos_angle = max(-1.0, min(1.0, dot / (mag1 * mag2)))
            angle = math.acos(cos_angle)
            angles.append(angle)

        if not angles:
            return 0.0

        # Calculate variance of angles
        # Humans: moderate variance (some curves, some straight)
        # Bots: very low variance (all straight) or artificially high
        return statistics.pstdev(angles) if len(angles) > 1 else 0.0

    @staticmethod
    def calculate_velocity_consistency(velocities: list[float]) -> float:
        """
        Analyze velocity changes. Humans accelerate/decelerate naturally.
        Bots often have instant velocity changes or constant velocity.
        
        Returns coefficient of variation (std/mean).
        """
        if len(velocities) < 2:
            return 0.0

        mean = statistics.mean(velocities)
        if mean == 0:
            return 0.0

        return statistics.pstdev(velocities) / mean

    @staticmethod
    def detect_teleportation(points: list[dict[str, float]], threshold: float = 100.0) -> int:
        """
        Detect impossible cursor jumps (teleportation).
        Returns count of teleport events.
        """
        teleports = 0
        for i in range(1, len(points)):
            dx = points[i]["x"] - points[i-1]["x"]
            dy = points[i]["y"] - points[i-1]["y"]
            dt = points[i].get("t", 0) - points[i-1].get("t", 0)

            if dt > 0:
                distance = math.sqrt(dx*dx + dy*dy)
                velocity = distance / dt  # pixels per millisecond

                # Human max cursor velocity ~ 3-5 px/ms with acceleration
                # Anything above 10 px/ms is suspicious
                if velocity > threshold:
                    teleports += 1

        return teleports


class KeystrokeAnalyzer:
    """Analyzes keystroke dynamics for bot detection."""

    @staticmethod
    def calculate_dwell_flight_ratio(keystrokes: list[dict[str, Any]]) -> dict[str, float]:
        """
        Calculate typing dynamics:
        - Dwell time: time a key is held down
        - Flight time: time between key releases and next press
        
        Humans have consistent but varied patterns.
        Bots often have zero dwell time or constant flight time.
        """
        if len(keystrokes) < 2:
            return {"dwell_cv": 0.0, "flight_cv": 0.0, "rhythm_score": 0.0}

        dwell_times: list[float] = []
        flight_times: list[float] = []

        for i, stroke in enumerate(keystrokes):
            # Dwell time (key down to key up)
            if "press_time" in stroke and "release_time" in stroke:
                dwell = stroke["release_time"] - stroke["press_time"]
                if dwell > 0:
                    dwell_times.append(dwell)

            # Flight time (release to next press)
            if i > 0:
                prev = keystrokes[i-1]
                if "release_time" in prev and "press_time" in stroke:
                    flight = stroke["press_time"] - prev["release_time"]
                    if flight > 0:
                        flight_times.append(flight)

        def cv(values: list[float]) -> float:
            if len(values) < 2:
                return 0.0
            mean = statistics.mean(values)
            if mean == 0:
                return 0.0
            return statistics.pstdev(values) / mean

        dwell_cv = cv(dwell_times) if dwell_times else 0.0
        flight_cv = cv(flight_times) if flight_times else 0.0

        # Rhythm score: humans have moderate CV (not too regular, not too random)
        # Optimal CV around 0.3-0.5 for both metrics
        rhythm_score = 1.0 - abs(0.4 - (dwell_cv + flight_cv) / 2)

        return {
            "dwell_cv": dwell_cv,
            "flight_cv": flight_cv,
            "rhythm_score": max(0.0, rhythm_score),
        }

    @staticmethod
    def detect_copy_paste(events: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Detect copy-paste behavior vs typing.
        """
        total_chars = sum(e.get("chars_added", 0) for e in events)
        paste_events = sum(1 for e in events if e.get("type") == "paste")
        rapid_inputs = sum(
            1 for i in range(1, len(events))
            if events[i].get("time", 0) - events[i-1].get("time", 0) < 10  # < 10ms gap
        )

        return {
            "total_chars": total_chars,
            "paste_events": paste_events,
            "rapid_inputs": rapid_inputs,
            "is_likely_paste": paste_events > 0 or (total_chars > 20 and rapid_inputs > 5),
        }


class ScrollPatternAnalyzer:
    """Analyzes scroll behavior for bot detection."""

    @staticmethod
    def analyze_scroll_dynamics(scroll_events: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Analyze scroll patterns:
        - Natural scrolling has acceleration/deceleration
        - Bot scrolling is often constant velocity or instant jumps
        """
        if len(scroll_events) < 3:
            return {"naturalness": 0.0, "direction_changes": 0, "avg_velocity": 0.0}

        velocities: list[float] = []
        direction_changes = 0

        for i in range(1, len(scroll_events)):
            dy = scroll_events[i].get("y", 0) - scroll_events[i-1].get("y", 0)
            dt = scroll_events[i].get("t", 0) - scroll_events[i-1].get("t", 0)

            if dt > 0:
                velocity = dy / dt
                velocities.append(velocity)

                # Detect direction changes (scroll up then down)
                if i > 1:
                    prev_vel = velocities[-2] if len(velocities) > 1 else 0
                    if (prev_vel > 0 and velocity < 0) or (prev_vel < 0 and velocity > 0):
                        direction_changes += 1

        if not velocities:
            return {"naturalness": 0.0, "direction_changes": 0, "avg_velocity": 0.0}

        # Naturalness: humans have varying velocities
        velocity_changes = [abs(velocities[i] - velocities[i-1]) for i in range(1, len(velocities))]
        naturalness = statistics.mean(velocity_changes) if velocity_changes else 0.0

        return {
            "naturalness": naturalness,
            "direction_changes": direction_changes,
            "avg_velocity": statistics.mean(velocities),
            "velocity_variance": statistics.pvariance(velocities) if len(velocities) > 1 else 0.0,
        }

    @staticmethod
    def detect_instant_scroll(scroll_events: list[dict[str, Any]], threshold: int = 500) -> bool:
        """
        Detect instant large scrolls (page up/down keys, wheel events without animation).
        """
        for i in range(1, len(scroll_events)):
            dy = abs(scroll_events[i].get("y", 0) - scroll_events[i-1].get("y", 0))
            dt = scroll_events[i].get("t", 0) - scroll_events[i-1].get("t", 0)

            # Large jump in small time = instant scroll
            if dy > threshold and dt < 50:  # 500px in 50ms
                return True

        return False


class EngagementAnalyzer:
    """Analyzes user engagement patterns."""

    @staticmethod
    def calculate_content_engagement(
        dwell_ms: int,
        content_length: int,
        scroll_depth: int,
        interaction_count: int,
    ) -> dict[str, Any]:
        """
        Calculate engagement metrics based on content length vs time spent.
        """
        if content_length == 0:
            engagement_ratio = 0.0
        else:
            # Rough reading speed: 200-300 words per minute = ~3-5 chars per second
            expected_read_time = (content_length / 4) * 1000  # ms
            engagement_ratio = dwell_ms / expected_read_time if expected_read_time > 0 else 0.0

        return {
            "engagement_ratio": engagement_ratio,
            "scroll_coverage": scroll_depth / 1000.0 if scroll_depth else 0.0,  # Normalize
            "interaction_density": interaction_count / (dwell_ms / 1000.0) if dwell_ms > 0 else 0.0,
            "is_engaged": engagement_ratio > 0.3 and scroll_depth > 100,
        }

    @staticmethod
    def detect_tab_abandonment(
        visibility_events: list[dict[str, Any]],
        focus_events: list[dict[str, Any]],
        dwell_ms: int,
    ) -> dict[str, Any]:
        """
        Detect if user switched tabs/windows frequently (possible bot multi-tasking).
        """
        visibility_switches = sum(1 for e in visibility_events if e.get("hidden", False))
        focus_losses = sum(1 for e in focus_events if e.get("type") == "blur")

        # Normal users might switch tabs 1-2 times
        # Bots running multiple sessions might switch constantly
        abandonment_score = (visibility_switches + focus_losses) / (dwell_ms / 60000.0) if dwell_ms > 0 else 0

        return {
            "visibility_switches": visibility_switches,
            "focus_losses": focus_losses,
            "abandonment_per_minute": abandonment_score,
            "is_suspicious": abandonment_score > 5,  # More than 5 switches per minute
        }


class AdvancedTrapDetector:
    """Advanced honeypot and trap mechanisms."""

    @staticmethod
    def check_honeypot_interaction(
        honeypot_id: str,
        interaction_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Check if hidden honeypot fields were interacted with.
        """
        honeypot_hits = [
            e for e in interaction_events
            if e.get("target_id") == honeypot_id or honeypot_id in str(e.get("target_class", ""))
        ]

        return {
            "honeypot_id": honeypot_id,
            "hit_count": len(honeypot_hits),
            "first_hit_time": honeypot_hits[0].get("time") if honeypot_hits else None,
            "is_bot": len(honeypot_hits) > 0,
        }

    @staticmethod
    def check_timing_trap(start_time: int, interaction_time: int, min_human_time: int = 2000) -> bool:
        """
        Check if form was filled faster than humanly possible.
        """
        elapsed = interaction_time - start_time
        return elapsed < min_human_time


# ============================================================================
# Main Scoring Functions
# ============================================================================

def score_advanced_mouse_patterns(
    mouse_data: dict[str, Any],
    weights: ScoringWeights | None = None,
) -> BehavioralScoreOutcome:
    """
    Score advanced mouse movement patterns.
    """
    reasons: list[str] = []
    risk_flags: list[str] = []
    delta = 0.0

    points = mouse_data.get("points", [])
    velocities = mouse_data.get("velocities", [])

    if len(points) >= 3:
        analyzer = MousePatternAnalyzer()

        # Check for teleportation
        teleports = analyzer.detect_teleportation(points)
        if teleports > 0:
            delta -= 15.0 * min(teleports, 3)  # Cap at -45
            reasons.append(f"behavior:mouse_teleport_{teleports}")
            risk_flags.append("MOUSE_TELEPORT")

        # Check jaggedness
        jaggedness = analyzer.calculate_jaggedness(points)
        if jaggedness < 0.05:  # Too straight = bot-like
            delta -= 8.0
            reasons.append("behavior:mouse_too_straight")
            risk_flags.append("MOBOT")
        elif jaggedness > 1.5:  # Too jagged = fake random
            delta -= 6.0
            reasons.append("behavior:mouse_too_jagged")

        # Velocity consistency
        if velocities:
            cv = analyzer.calculate_velocity_consistency(velocities)
            if cv < 0.1:  # Too consistent = bot
                delta -= 10.0
                reasons.append("behavior:mouse_constant_velocity")
                risk_flags.append("CONSTANT_VELOCITY")

    return BehavioralScoreOutcome(delta=delta, reasons=reasons, risk_flags=risk_flags)


def score_advanced_keystrokes(
    keystroke_data: list[dict[str, Any]],
    weights: ScoringWeights | None = None,
) -> BehavioralScoreOutcome:
    """
    Score keystroke dynamics.
    """
    reasons: list[str] = []
    risk_flags: list[str] = []
    delta = 0.0

    if not keystroke_data:
        return BehavioralScoreOutcome(delta=0.0, reasons=[], risk_flags=[])

    analyzer = KeystrokeAnalyzer()

    # Check for copy-paste
    paste_check = analyzer.detect_copy_paste(keystroke_data)
    if paste_check["is_likely_paste"]:
        delta -= 5.0
        reasons.append("behavior:likely_copy_paste")

    # Analyze typing rhythm
    rhythm = analyzer.calculate_dwell_flight_ratio(keystroke_data)
    dwell_cv = rhythm["dwell_cv"]
    flight_cv = rhythm["flight_cv"]

    # Perfectly consistent typing = bot
    if dwell_cv < 0.05 and len(keystroke_data) > 5:
        delta -= 15.0
        reasons.append("behavior:robotic_typing")
        risk_flags.append("ROBOTIC_TYPING")

    # Zero dwell time = instant key presses
    if rhythm["rhythm_score"] == 0.0 and len(keystroke_data) > 3:
        delta -= 10.0
        reasons.append("behavior:zero_dwell_time")
        risk_flags.append("ZERO_DWELL")

    # Good human-like typing
    if 0.2 <= dwell_cv <= 0.8 and 0.2 <= flight_cv <= 0.8:
        delta += 5.0
        reasons.append("behavior:human_typing_pattern")

    return BehavioralScoreOutcome(delta=delta, reasons=reasons, risk_flags=risk_flags)


def score_advanced_scroll_patterns(
    scroll_data: list[dict[str, Any]],
    weights: ScoringWeights | None = None,
) -> BehavioralScoreOutcome:
    """
    Score scroll behavior patterns.
    """
    reasons: list[str] = []
    risk_flags: list[str] = []
    delta = 0.0

    if not scroll_data:
        return BehavioralScoreOutcome(delta=0.0, reasons=[], risk_flags=[])

    analyzer = ScrollPatternAnalyzer()

    # Detect instant scrolls
    if analyzer.detect_instant_scroll(scroll_data):
        delta -= 12.0
        reasons.append("behavior:instant_scroll")
        risk_flags.append("INSTANT_SCROLL")

    # Analyze dynamics
    dynamics = analyzer.analyze_scroll_dynamics(scroll_data)

    # Very low naturalness = mechanical scrolling
    if dynamics["naturalness"] < 0.5 and len(scroll_data) > 5:
        delta -= 8.0
        reasons.append("behavior:mechanical_scroll")

    # Excessive direction changes (possible scroll bot testing)
    if dynamics["direction_changes"] > 10:
        delta -= 5.0
        reasons.append(f"behavior:excessive_scroll_directions_{dynamics['direction_changes']}")

    return BehavioralScoreOutcome(delta=delta, reasons=reasons, risk_flags=risk_flags)


def score_engagement_patterns(
    engagement_data: dict[str, Any],
    weights: ScoringWeights | None = None,
) -> BehavioralScoreOutcome:
    """
    Score content engagement patterns.
    """
    reasons: list[str] = []
    risk_flags: list[str] = []
    delta = 0.0

    analyzer = EngagementAnalyzer()

    # Calculate engagement
    engagement = analyzer.calculate_content_engagement(
        dwell_ms=engagement_data.get("dwell_ms", 0),
        content_length=engagement_data.get("content_length", 0),
        scroll_depth=engagement_data.get("scroll_depth", 0),
        interaction_count=engagement_data.get("interaction_count", 0),
    )

    # Very low engagement on long content = suspicious
    if engagement["engagement_ratio"] < 0.1 and engagement_data.get("content_length", 0) > 1000:
        delta -= 10.0
        reasons.append("behavior:low_engagement_long_content")

    # High engagement
    if engagement["is_engaged"]:
        delta += 8.0
        reasons.append("behavior:good_engagement")

    # Check for tab abandonment
    abandonment = analyzer.detect_tab_abandonment(
        visibility_events=engagement_data.get("visibility_events", []),
        focus_events=engagement_data.get("focus_events", []),
        dwell_ms=engagement_data.get("dwell_ms", 0),
    )

    if abandonment["is_suspicious"]:
        delta -= 8.0
        reasons.append(f"behavior:excessive_tab_switching")
        risk_flags.append("TAB_ABANDONMENT")

    return BehavioralScoreOutcome(delta=delta, reasons=reasons, risk_flags=risk_flags)


def score_traps(
    trap_data: dict[str, Any],
    weights: ScoringWeights | None = None,
) -> BehavioralScoreOutcome:
    """
    Score honeypot and timing trap hits.
    """
    reasons: list[str] = []
    risk_flags: list[str] = []
    delta = 0.0

    detector = AdvancedTrapDetector()

    # Check honeypots
    for honeypot_id, events in trap_data.get("honeypots", {}).items():
        result = detector.check_honeypot_interaction(honeypot_id, events)
        if result["is_bot"]:
            delta -= 25.0
            reasons.append(f"trap:honeypot_hit_{honeypot_id}")
            risk_flags.append("HONEYPOT_HIT")

    # Check timing traps
    for timing_trap in trap_data.get("timing_traps", []):
        if detector.check_timing_trap(
            timing_trap.get("start_time", 0),
            timing_trap.get("interaction_time", 0),
        ):
            delta -= 20.0
            reasons.append("trap:impossible_timing")
            risk_flags.append("TIMING_TRAP")

    return BehavioralScoreOutcome(delta=delta, reasons=reasons, risk_flags=risk_flags)


def score_phase2_behavioral(
    beacon_data: dict[str, Any],
    session: dict[str, Any],
    weights: ScoringWeights | None = None,
) -> BehavioralScoreOutcome:
    """
    Main entry point for Stage 2 Phase 2 behavioral scoring.
    Combines all advanced behavioral analyses.
    """
    total_delta = 0.0
    all_reasons: list[str] = []
    all_risks: list[str] = []

    # Score mouse patterns
    if "mouse_data" in beacon_data:
        mouse_result = score_advanced_mouse_patterns(beacon_data["mouse_data"], weights)
        total_delta += mouse_result.delta
        all_reasons.extend(mouse_result.reasons)
        all_risks.extend(mouse_result.risk_flags)

    # Score keystrokes
    if "keystrokes" in beacon_data:
        keystroke_result = score_advanced_keystrokes(beacon_data["keystrokes"], weights)
        total_delta += keystroke_result.delta
        all_reasons.extend(keystroke_result.reasons)
        all_risks.extend(keystroke_result.risk_flags)

    # Score scroll patterns
    if "scroll_data" in beacon_data:
        scroll_result = score_advanced_scroll_patterns(beacon_data["scroll_data"], weights)
        total_delta += scroll_result.delta
        all_reasons.extend(scroll_result.reasons)
        all_risks.extend(scroll_result.risk_flags)

    # Score engagement
    if "engagement" in beacon_data:
        engagement_result = score_engagement_patterns(beacon_data["engagement"], weights)
        total_delta += engagement_result.delta
        all_reasons.extend(engagement_result.reasons)
        all_risks.extend(engagement_result.risk_flags)

    # Score traps
    if "traps" in beacon_data:
        trap_result = score_traps(beacon_data["traps"], weights)
        total_delta += trap_result.delta
        all_reasons.extend(trap_result.reasons)
        all_risks.extend(trap_result.risk_flags)

    return BehavioralScoreOutcome(
        delta=total_delta,
        reasons=all_reasons,
        risk_flags=all_risks,
    )
