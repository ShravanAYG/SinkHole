"""
Website Build Suite — Test Framework for SinkHole Botwall

Provides tools to build test websites, generate test scenarios,
and automate bot/human behavior simulation for testing the botwall.
"""

from __future__ import annotations

import json
import random
import string
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TestWebsiteConfig:
    """Configuration for a test website."""
    name: str = "Test Site"
    pages: int = 5
    content_length_range: tuple[int, int] = (500, 2000)
    has_forms: bool = True
    has_search: bool = True
    protection_level: str = "standard"  # minimal, standard, maximum
    include_honeypots: bool = True
    include_timing_traps: bool = True


@dataclass
class TestScenario:
    """A test scenario definition."""
    name: str
    behavior_type: str  # "human", "bot_basic", "bot_advanced", "mixed"
    session_count: int = 1
    pages_to_visit: list[int] = field(default_factory=list)
    interaction_pattern: dict[str, Any] = field(default_factory=dict)
    expected_outcome: str = "allow"  # allow, challenge, decoy


class ContentGenerator:
    """Generates synthetic content for test websites."""

    TOPICS = [
        "technology", "science", "history", "art", "music",
        "sports", "cooking", "travel", "finance", "health",
    ]

    @staticmethod
    def generate_paragraph(min_words: int = 50, max_words: int = 200) -> str:
        """Generate a random paragraph."""
        word_count = random.randint(min_words, max_words)
        words = []
        for _ in range(word_count):
            length = random.randint(3, 12)
            word = ''.join(random.choices(string.ascii_lowercase, k=length))
            words.append(word)
        return ' '.join(words).capitalize() + "."

    @staticmethod
    def generate_article(title: str, min_paragraphs: int = 3, max_paragraphs: int = 8) -> str:
        """Generate a complete article."""
        paragraphs = []
        for i in range(random.randint(min_paragraphs, max_paragraphs)):
            paragraphs.append(ContentGenerator.generate_paragraph())
        return f"<h1>{title}</h1>" + ''.join(f"<p>{p}</p>" for p in paragraphs)

    @staticmethod
    def generate_form_fields(count: int = 3) -> list[dict[str, Any]]:
        """Generate form field definitions."""
        field_types = ["text", "email", "textarea", "select", "checkbox"]
        fields = []
        for i in range(count):
            field_type = random.choice(field_types)
            field = {
                "name": f"field_{i}",
                "type": field_type,
                "label": f"Field {i}",
                "required": random.choice([True, False]),
            }
            if field_type == "select":
                field["options"] = [f"Option {j}" for j in range(3, 6)]
            fields.append(field)
        return fields


class HoneypotGenerator:
    """Generates honeypot fields and traps."""

    HONEYPOT_NAMES = [
        "website", "url", "homepage", "company", "department",
        "fax", "phone_ext", "alternate_email", "comments2",
    ]

    @staticmethod
    def generate_honeypot_field() -> dict[str, Any]:
        """Generate a honeypot form field."""
        name = random.choice(HoneypotGenerator.HONEYPOT_NAMES)
        return {
            "id": f"hp_{name}_{random.randint(1000, 9999)}",
            "name": name,
            "type": "text",
            "css_class": f"form-field {random.choice(['optional', 'hidden-field', 'secondary'])}",
            "tabindex": -1,
            "autocomplete": "off",
            "aria_hidden": "true",
            "style": "position:absolute;left:-9999px;top:-9999px;",
        }

    @staticmethod
    def generate_timing_trap() -> dict[str, Any]:
        """Generate timing trap configuration."""
        return {
            "min_human_time_ms": random.randint(1500, 3000),
            "trap_id": f"timing_trap_{random.randint(1000, 9999)}",
            "field_name": random.choice(["email", "message", "subject"]),
        }


class TestWebsiteBuilder:
    """Builds a complete test website with botwall integration."""

    def __init__(self, config: TestWebsiteConfig | None = None):
        self.config = config or TestWebsiteConfig()
        self.content_gen = ContentGenerator()
        self.honeypot_gen = HoneypotGenerator()
        self.pages: list[dict[str, Any]] = []

    def build(self) -> dict[str, Any]:
        """Build the complete website structure."""
        self.pages = []

        for i in range(self.config.pages):
            page = self._build_page(i)
            self.pages.append(page)

        return {
            "config": self._config_to_dict(),
            "pages": self.pages,
            "forms": self._build_forms() if self.config.has_forms else [],
            "honeypots": self._build_honeypots() if self.config.include_honeypots else [],
            "timing_traps": self._build_timing_traps() if self.config.include_timing_traps else [],
            "navigation": self._build_navigation(),
        }

    def _config_to_dict(self) -> dict[str, Any]:
        return {
            "name": self.config.name,
            "pages": self.config.pages,
            "has_forms": self.config.has_forms,
            "has_search": self.config.has_search,
            "protection_level": self.config.protection_level,
            "include_honeypots": self.config.include_honeypots,
            "include_timing_traps": self.config.include_timing_traps,
        }

    def _build_page(self, page_id: int) -> dict[str, Any]:
        """Build a single page."""
        title = f"Page {page_id + 1} - {random.choice(self.content_gen.TOPICS).title()}"
        content_length = random.randint(*self.config.content_length_range)

        # Generate content
        paragraphs_needed = max(1, content_length // 150)
        content = self.content_gen.generate_article(title, paragraphs_needed, paragraphs_needed + 2)

        return {
            "id": page_id,
            "path": f"/content/{page_id}",
            "title": title,
            "content_length": content_length,
            "content": content,
            "has_form": self.config.has_forms and random.random() > 0.3,
            "links_to": [(page_id + i) % self.config.pages for i in range(1, 4)],
        }

    def _build_forms(self) -> list[dict[str, Any]]:
        """Build form definitions."""
        forms = []
        for page in self.pages:
            if page["has_form"]:
                form_fields = self.content_gen.generate_form_fields(random.randint(2, 5))
                forms.append({
                    "page_id": page["id"],
                    "form_id": f"form_{page['id']}_{random.randint(1000, 9999)}",
                    "action": f"/submit/{page['id']}",
                    "method": "POST",
                    "fields": form_fields,
                })
        return forms

    def _build_honeypots(self) -> list[dict[str, Any]]:
        """Build honeypot definitions."""
        honeypots = []
        for form in self._build_forms():
            # Add 1-2 honeypots per form
            for _ in range(random.randint(1, 2)):
                hp = self.honeypot_gen.generate_honeypot_field()
                hp["parent_form"] = form["form_id"]
                honeypots.append(hp)

        # Add page-level honeypots (hidden links)
        for page in self.pages:
            if random.random() > 0.5:
                honeypots.append({
                    "id": f"hp_link_{page['id']}_{random.randint(1000, 9999)}",
                    "type": "hidden_link",
                    "page_id": page["id"],
                    "href": "/admin/secret-panel",
                    "css_class": "admin-link hidden",
                    "style": "display:none;",
                    "text": "Admin Panel",
                })

        return honeypots

    def _build_timing_traps(self) -> list[dict[str, Any]]:
        """Build timing trap definitions."""
        traps = []
        for form in self._build_forms():
            trap = self.honeypot_gen.generate_timing_trap()
            trap["form_id"] = form["form_id"]
            traps.append(trap)
        return traps

    def _build_navigation(self) -> dict[str, Any]:
        """Build navigation structure."""
        return {
            "main_menu": [p["path"] for p in self.pages[:4]],
            "footer_links": [p["path"] for p in self.pages[-3:]],
            "search_path": "/search" if self.config.has_search else None,
        }


class BehaviorSimulator:
    """Simulates different user behaviors for testing."""

    @staticmethod
    def simulate_human_mouse_path(start: tuple[float, float], end: tuple[float, float]) -> list[dict[str, Any]]:
        """
        Generate realistic human-like mouse path.
        Humans make slightly curved, imperfect lines.
        """
        points = []
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        distance = (dx**2 + dy**2) ** 0.5

        # Number of intermediate points based on distance
        num_points = max(3, int(distance / 20))

        for i in range(num_points + 1):
            t = i / num_points

            # Linear interpolation with noise for human-like curve
            base_x = start[0] + dx * t
            base_y = start[1] + dy * t

            # Add perpendicular noise for curve
            if 0 < i < num_points:
                # Perpendicular offset
                perp_x = -dy / distance if distance > 0 else 0
                perp_y = dx / distance if distance > 0 else 0
                noise = random.gauss(0, distance * 0.05)  # 5% deviation
                base_x += perp_x * noise
                base_y += perp_y * noise

            # Add small random jitter
            base_x += random.gauss(0, 2)
            base_y += random.gauss(0, 2)

            # Time with human-like velocity curve (accelerate then decelerate)
            time_offset = (t ** 1.5) * (distance / 0.5)  # 0.5 px/ms avg velocity

            points.append({
                "x": round(base_x, 2),
                "y": round(base_y, 2),
                "t": round(time_offset, 2),
            })

        return points

    @staticmethod
    def simulate_bot_mouse_path(start: tuple[float, float], end: tuple[float, float]) -> list[dict[str, Any]]:
        """
        Generate bot-like mouse path (straight line, constant velocity).
        """
        points = []
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        distance = (dx**2 + dy**2) ** 0.5

        # Fewer points, straight line
        num_points = max(2, int(distance / 50))

        for i in range(num_points + 1):
            t = i / num_points
            x = start[0] + dx * t
            y = start[1] + dy * t
            # Constant time increments = constant velocity
            time_offset = t * (distance / 2.0)  # 2 px/ms = fast

            points.append({
                "x": round(x, 2),
                "y": round(y, 2),
                "t": round(time_offset, 2),
            })

        return points

    @staticmethod
    def simulate_human_keystrokes(text: str) -> list[dict[str, Any]]:
        """
        Generate human-like keystroke timing.
        """
        keystrokes = []
        current_time = 0.0

        for char in text:
            # Dwell time (how long key is held)
            # Humans: 80-150ms average with variation
            dwell = max(20, random.gauss(120, 40))

            # Flight time (time between releasing one key and pressing next)
            # Humans: 50-200ms with variation based on character transitions
            flight = max(10, random.gauss(100, 50))

            press_time = current_time
            release_time = current_time + dwell

            keystrokes.append({
                "char": char,
                "press_time": round(press_time, 2),
                "release_time": round(release_time, 2),
                "dwell": round(dwell, 2),
            })

            current_time = release_time + flight

        return keystrokes

    @staticmethod
    def simulate_bot_keystrokes(text: str) -> list[dict[str, Any]]:
        """
        Generate bot-like keystroke timing.
        """
        keystrokes = []
        current_time = 0.0

        # Bots often type very fast with minimal variation
        for char in text:
            # Very fast, consistent timing
            dwell = 10  # 10ms = instant
            flight = 5   # 5ms gap

            keystrokes.append({
                "char": char,
                "press_time": round(current_time, 2),
                "release_time": round(current_time + dwell, 2),
                "dwell": dwell,
            })

            current_time += dwell + flight

        return keystrokes

    @staticmethod
    def simulate_human_scroll(content_height: int = 2000) -> list[dict[str, Any]]:
        """
        Generate human-like scroll pattern.
        """
        scroll_events = []
        current_y = 0
        current_time = 0.0

        # Humans scroll in bursts with pauses
        while current_y < content_height:
            # Burst of scroll events
            burst_size = random.randint(3, 8)
            for _ in range(burst_size):
                # Variable scroll amount
                delta = random.randint(30, 100)
                current_y += delta
                # Variable time between scrolls
                current_time += random.uniform(16, 50)  # 16-50ms (1-3 frames)

                scroll_events.append({
                    "y": min(current_y, content_height),
                    "t": round(current_time, 2),
                    "delta": delta,
                })

            # Pause between bursts
            current_time += random.uniform(300, 2000)  # 0.3-2 second pause

            if current_y >= content_height:
                break

        return scroll_events

    @staticmethod
    def simulate_bot_scroll(content_height: int = 2000) -> list[dict[str, Any]]:
        """
        Generate bot-like scroll (instant jump to bottom).
        """
        return [
            {"y": 0, "t": 0, "delta": 0},
            {"y": content_height, "t": 50, "delta": content_height},  # Instant jump
        ]


class TestSuite:
    """Main test suite for running botwall scenarios."""

    def __init__(self):
        self.websites: list[dict[str, Any]] = []
        self.scenarios: list[TestScenario] = []
        self.results: list[dict[str, Any]] = []

    def create_website(self, config: TestWebsiteConfig | None = None) -> dict[str, Any]:
        """Create a test website."""
        builder = TestWebsiteBuilder(config)
        website = builder.build()
        self.websites.append(website)
        return website

    def add_scenario(self, scenario: TestScenario) -> None:
        """Add a test scenario."""
        self.scenarios.append(scenario)

    def generate_default_scenarios(self) -> list[TestScenario]:
        """Generate default test scenarios."""
        return [
            TestScenario(
                name="Human browsing session",
                behavior_type="human",
                session_count=1,
                pages_to_visit=[0, 1, 2],
                interaction_pattern={
                    "mouse": "human",
                    "scroll": "human",
                    "dwell_range": [2000, 8000],
                    "form_interaction": True,
                },
                expected_outcome="allow",
            ),
            TestScenario(
                name="Basic bot scraper",
                behavior_type="bot_basic",
                session_count=1,
                pages_to_visit=[0, 1, 2, 3, 4],
                interaction_pattern={
                    "mouse": "none",
                    "scroll": "instant",
                    "dwell_range": [200, 500],
                    "form_interaction": False,
                },
                expected_outcome="decoy",
            ),
            TestScenario(
                name="Advanced bot with mouse simulation",
                behavior_type="bot_advanced",
                session_count=1,
                pages_to_visit=[0, 1, 2],
                interaction_pattern={
                    "mouse": "bot_linear",
                    "scroll": "bot_smooth",
                    "dwell_range": [1000, 2000],
                    "form_interaction": True,
                },
                expected_outcome="challenge",  # Should catch the linear mouse
            ),
            TestScenario(
                name="Honeypot interaction test",
                behavior_type="bot_basic",
                session_count=1,
                pages_to_visit=[0],
                interaction_pattern={
                    "interact_honeypots": True,
                    "mouse": "none",
                    "scroll": "instant",
                    "dwell_range": [100, 300],
                },
                expected_outcome="decoy",
            ),
            TestScenario(
                name="Timing trap test",
                behavior_type="bot_basic",
                session_count=1,
                pages_to_visit=[0],
                interaction_pattern={
                    "form_fill_time_ms": 200,  # Impossibly fast
                    "mouse": "bot_linear",
                    "scroll": "instant",
                },
                expected_outcome="decoy",
            ),
        ]

    def run_scenario(self, scenario: TestScenario) -> dict[str, Any]:
        """Run a single test scenario and return results."""
        results = {
            "scenario": scenario.name,
            "behavior_type": scenario.behavior_type,
            "expected_outcome": scenario.expected_outcome,
            "sessions": [],
            "passed": False,
        }

        for session_idx in range(scenario.session_count):
            session_result = self._simulate_session(scenario, session_idx)
            results["sessions"].append(session_result)

        # Check if outcomes match expectations
        actual_outcomes = [s["final_decision"] for s in results["sessions"]]
        results["passed"] = all(o == scenario.expected_outcome for o in actual_outcomes)

        return results

    def _simulate_session(
        self,
        scenario: TestScenario,
        session_idx: int,
    ) -> dict[str, Any]:
        """Simulate a single session."""
        simulator = BehaviorSimulator()

        session_data = {
            "session_idx": session_idx,
            "pages_visited": [],
            "beacons": [],
            "final_decision": "unknown",
        }

        for page_id in scenario.pages_to_visit:
            page_data: dict[str, Any] = {
                "page_id": page_id,
                "events": [],
            }

            pattern = scenario.interaction_pattern

            # Simulate mouse movements if configured
            if pattern.get("mouse") == "human":
                # Random start and end points
                start = (random.uniform(0, 800), random.uniform(0, 600))
                end = (random.uniform(0, 800), random.uniform(0, 600))
                page_data["mouse_path"] = simulator.simulate_human_mouse_path(start, end)
            elif pattern.get("mouse") == "bot_linear":
                start = (random.uniform(0, 800), random.uniform(0, 600))
                end = (random.uniform(0, 800), random.uniform(0, 600))
                page_data["mouse_path"] = simulator.simulate_bot_mouse_path(start, end)

            # Simulate scroll
            if pattern.get("scroll") == "human":
                page_data["scroll_events"] = simulator.simulate_human_scroll()
            elif pattern.get("scroll") in ["instant", "bot_smooth"]:
                page_data["scroll_events"] = simulator.simulate_bot_scroll()

            # Simulate dwell time
            dwell_range = pattern.get("dwell_range", [1000, 3000])
            page_data["dwell_ms"] = random.randint(dwell_range[0], dwell_range[1])

            # Simulate form interactions
            if pattern.get("form_interaction"):
                form_text = "This is a test message for the form."
                if scenario.behavior_type.startswith("bot"):
                    page_data["keystrokes"] = simulator.simulate_bot_keystrokes(form_text)
                else:
                    page_data["keystrokes"] = simulator.simulate_human_keystrokes(form_text)

            # Check for honeypot hits
            if pattern.get("interact_honeypots"):
                page_data["honeypot_hits"] = ["hp_website_1234", "hp_url_5678"]

            # Check timing trap
            if "form_fill_time_ms" in pattern:
                page_data["form_fill_time_ms"] = pattern["form_fill_time_ms"]

            session_data["pages_visited"].append(page_data)

        return session_data

    def run_all(self) -> dict[str, Any]:
        """Run all scenarios and return summary."""
        self.results = []

        for scenario in self.scenarios:
            result = self.run_scenario(scenario)
            self.results.append(result)

        total = len(self.results)
        passed = sum(1 for r in self.results if r["passed"])

        return {
            "total_scenarios": total,
            "passed": passed,
            "failed": total - passed,
            "success_rate": passed / total if total > 0 else 0.0,
            "results": self.results,
        }


def create_demo_test_suite() -> TestSuite:
    """Create a demo test suite with sample websites and scenarios."""
    suite = TestSuite()

    # Create test website
    config = TestWebsiteConfig(
        name="Demo E-Commerce Site",
        pages=7,
        has_forms=True,
        has_search=True,
        protection_level="maximum",
        include_honeypots=True,
        include_timing_traps=True,
    )
    suite.create_website(config)

    # Add default scenarios
    for scenario in suite.generate_default_scenarios():
        suite.add_scenario(scenario)

    return suite
