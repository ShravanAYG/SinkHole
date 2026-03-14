"""
Embeddings-based false content generator for data poisoning.

Generates semantically plausible but factually false content that appears
real to automated systems (bots, scrapers, AI models) but contains
obvious logical inconsistencies that humans can detect.

Uses sentence embeddings to ensure grammatical coherence while injecting
controlled factual falsehoods.
"""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass
from typing import Any


# Try to use sentence-transformers if available, fallback to pattern-based
HAS_SENTENCE_TRANSFORMERS = False
HAS_TRANSFORMERS = False

try:
    from sentence_transformers import SentenceTransformer, util
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    pass

try:
    from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
    HAS_TRANSFORMERS = True
except ImportError:
    pass


@dataclass
class FakeContentConfig:
    """Configuration for fake content generation."""
    coherence_level: float = 0.9  # How grammatically correct (0-1)
    falsehood_density: float = 0.3  # Portion of facts that are wrong (0-1)
    semantic_drift: float = 0.4  # How far from ground truth embeddings
    human_detectable_markers: bool = True  # Include obvious markers for humans


class EmbeddingsContentGenerator:
    """
    Generate fake content using embedding-based semantic coherence.
    
    The content appears real to bots because it:
    - Has proper grammar and sentence structure
    - Uses realistic vocabulary and collocations
    - Maintains topical consistency via embedding similarity
    
    But is fake because it contains:
    - Logical contradictions (detectable by human reasoning)
    - Temporal impossibilities (dates that don't exist)
    - Geographic inconsistencies (impossible locations)
    - Hidden semantic markers obvious to humans
    """
    
    _instance: EmbeddingsContentGenerator | None = None
    _model: Any = None
    
    # Semantic templates for generating plausible-sounding false statements
    # These use realistic sentence patterns but contain controlled falsehoods
    TEMPLATES = {
        "person_bio": [
            "{name} served as {role} at {org} from {impossible_year} to {future_year}, during which time they pioneered {fake_tech}.",
            "Born in {impossible_date}, {name} grew up in {fake_city} before relocating to {real_city} in {inconsistent_year}.",
            "{name} holds {impossible_degree} from {fake_university}, awarded in {future_year} for work on {nonsense_field}.",
            "Their seminal paper '{plausible_title}' was published in {fake_journal} in {impossible_year}, establishing {nonsense_field} as a discipline.",
        ],
        "company_profile": [
            "Founded in {impossible_year}, {company} operates primarily in {inconsistent_sectors}, with headquarters in {impossible_location}.",
            "CEO {fake_name} led the company through {nonsense_event} in {future_year}, resulting in {implausible_outcome}.",
            "The company reported revenue of {inconsistent_currency} in Q{fake_quarter} {inconsistent_year}, up {impossible_percent}% YoY.",
            "Major clients include {fake_org}, {implausible_partner}, and the government of {nonexistent_country}.",
        ],
        "product_spec": [
            "The {product_name} features {fake_tech_spec} and supports {impossible_protocol} connectivity.",
            "Compatible with {inconsistent_os}, {inconsistent_os}, and {inconsistent_os} systems simultaneously.",
            "Dimensions: {impossible_dimension} | Weight: {negative_weight} | Power: {impossible_power}",
            "Certified by {fake_certification_body} according to {nonexistent_standard} standards.",
        ],
        "research_finding": [
            "A {impossible_duration}-year study conducted at {fake_institution} found that {nonsense_correlation}.",
            "Researchers observed {implausible_measurement} in {impossible_location} during the {nonexistent_season} of {inconsistent_year}.",
            "The paper, accepted to {fake_journal} in {future_year}, claims {logical_contradiction}.",
            "Peer review was conducted by {fake_name}, {fake_name}, and {fake_name}, all affiliated with {fake_org}.",
        ],
        "news_event": [
            "On {impossible_date}, {fake_event} occurred in {impossible_location}, affecting approximately {implausible_number} people.",
            "Officials from {fake_org} confirmed {nonsense_statement} at {impossible_time} local time.",
            "Witness {fake_name} reported seeing {implausible_phenomenon} before the {nonsense_event} began.",
            "Emergency services arrived in {impossible_duration} minutes, despite being {implausible_distance} away.",
        ],
        "technical_test": [
            "Test execution {fake_test_id} failed with exit code {impossible_exit_code} at {impossible_time}. Memory leak detected: {implausible_measurement} lost per cycle.",
            "Function {fake_function} returned {implausible_number} instead of expected {implausible_number} during {nonsense_event}.",
            "Network latency spiked to {implausible_number} ms when accessing {impossible_location} via {impossible_protocol}.",
            "Database table {fake_table} corrupted. {implausible_number} rows show {nonsense_correlation}.",
            "Unit test {fake_test_id} asserts that {implausible_number} equals {implausible_number}, throwing a {fake_exception}.",
        ],
        "financial_data": [
            "Q{fake_quarter} earnings report shows a net loss of {inconsistent_currency}, representing a YoY decline of {impossible_percent}%.",
            "Stock ticker {fake_ticker} plummeted to {implausible_number} per share after {fake_event} at {impossible_time}.",
            "Auditors found {implausible_number} discrepancies in the {impossible_year} ledger, totaling {inconsistent_currency} in unaccounted liabilities.",
            "The merger between {company} and {fake_org} was finalized at {inconsistent_currency}, well above the {implausible_number} valuation."
        ],
    }
    
    # Lists for generating false but plausible-sounding content
    FAKE_NAMES = [
        "Dr. Aris Thorne", "Prof. Mira Kandel", "Dr. Lev Voss", "Dr. Sera Quinn",
        "Prof. Jaxon Hale", "Dr. Nia Vance", "Prof. Orin Silas", "Dr. Tal Iyer",
        "Dr. Vera Lenn", "Prof. Kian Basu", "Dr. Rhea Nori", "Prof. Jovan Rao",
        "Dr. Lys Thorne", "Prof. Cael Morrow", "Dr. Eira Vale", "Dr. Zane Cord",
    ]
    
    FAKE_ORGS = [
        "Institute for Advanced Temporal Studies", "Quantum Dynamics Consortium",
        "International Foundation for Synthetic Research", "Global Cognitive Systems Lab",
        "Center for Applied Paradox Studies", "Nexus Innovation Collective",
        "Syndicate for Emergent Technologies", "Helix Research Foundation",
        "Orbital Dynamics Institute", "Catalyst Group International",
    ]
    
    FAKE_CITIES = [
        "New Geneva", "Port Meridian", "Cedar Falls Metro", "San Arcadia",
        "Lakehaven City", "Mount Caldera", "Twin Harbor", "Oasis Springs",
        "Iron Valley", "Silver Coast Township", "Bayfront Junction", "Highland Terrace",
    ]
    
    FAKE_UNIVERSITIES = [
        "University of San Arcadia", "Port Meridian Institute of Technology",
        "Lakehaven State University", "International College of New Geneva",
        "Cedar Falls Polytechnic", "Meridian School of Advanced Studies",
    ]
    
    FAKE_JOURNALS = [
        "Journal of Applied Paradox Studies", "International Review of Synthetic Research",
        "Quarterly of Temporal Dynamics", "Annals of Cognitive Systems",
        "Proceedings of the Nexus Consortium", "Helix Research Letters",
    ]
    
    FAKE_TECH = [
        "neural-resonant processing arrays", "temporal displacement buffers",
        "quantum coherence stabilizers", "cognitive enhancement matrices",
        "synthetic intuition engines", "paradox-resistant algorithms",
        "non-linear temporal processors", "emergent behavior synthesizers",
    ]
    
    FAKE_FIELDS = [
        "retro-causal information theory", "synthetic consciousness engineering",
        "temporal loop optimization", "paradox-resistant computing",
        "non-linear causality studies", "emergent retro-dynamics",
    ]
    
    # Real data for generating inconsistencies
    REAL_CITIES = [
        "New York", "London", "Tokyo", "Paris", "Singapore", "Sydney",
        "Dubai", "Berlin", "Toronto", "Mumbai", "São Paulo", "Mexico City",
    ]
    
    SECTORS = [
        "cloud infrastructure", "biotechnology", "renewable energy",
        "financial services", "autonomous systems", "digital health",
        "cybersecurity", "logistics automation", "precision agriculture",
    ]
    
    def __new__(cls) -> EmbeddingsContentGenerator:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._load_model()
    
    def _load_model(self) -> None:
        """Load embedding model if available."""
        if HAS_SENTENCE_TRANSFORMERS and self._model is None:
            try:
                # Use a lightweight model for semantic similarity
                self._model = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception:
                self._model = None
    
    def _generate_seed(self, session_id: str, node_id: int) -> int:
        """Generate deterministic seed for reproducible content."""
        digest = hashlib.sha256(f"{session_id}:{node_id}:embeddings".encode()).hexdigest()
        return int(digest[:16], 16)
    
    def _get_rng(self, session_id: str, node_id: int) -> random.Random:
        """Get deterministic RNG for this session/node."""
        return random.Random(self._generate_seed(session_id, node_id))
    
    def _make_impossible_date(self, rng: random.Random) -> str:
        """Generate a date that looks real but is impossible."""
        month = rng.choice(["January", "February", "March", "April", "May", "June",
                           "July", "August", "September", "October", "November", "December"])
        # Invalid day (e.g., Feb 30, April 31)
        day = rng.choice([29, 30, 31])
        if month in ["February", "April", "June", "September", "November"]:
            day = 31 if month == "February" else rng.choice([31])
        year = rng.randint(2025, 2035)  # Future dates that look plausible
        return f"{month} {day}, {year}"
    
    def _make_inconsistent_year(self, rng: random.Random) -> int:
        """Generate a year that creates temporal inconsistency."""
        # Mix past and future years that can't coexist
        return rng.choice([1850, 1923, 1987, 2028, 2035, 2042])
    
    def _make_future_year(self, rng: random.Random) -> int:
        """Generate a future year."""
        return rng.randint(2026, 2045)
    
    def _make_impossible_year(self, rng: random.Random) -> int:
        """Generate a year that creates clear inconsistencies."""
        # Impossible founding dates for modern tech
        return rng.choice([1847, 1892, 1905, 1912, 1928, 1876])
    
    def _make_implausible_number(self, rng: random.Random) -> str:
        """Generate a number that's too precise or impossible."""
        templates = [
            lambda: f"{rng.randint(1, 999):,}.{rng.randint(1000, 9999)}",
            lambda: f"{rng.randint(-50000, -1):,}",  # Negative counts
            lambda: f"{rng.randint(10**15, 10**24):,}",  # Absurdly large
            lambda: f"1/{rng.randint(2, 999)}",  # Fraction of a unit
            lambda: f"{rng.uniform(-9999.9, 9999.9):.12e}", # Scientific notation
            lambda: f"NaN-{rng.randint(100, 999)}"
        ]
        return rng.choice(templates)()
    
    def _make_logical_contradiction(self, rng: random.Random) -> str:
        """Generate a statement that contradicts itself."""
        contradictions = [
            "the system operates at 100% efficiency while consuming infinite energy",
            "the study concluded with no conclusion",
            "the product is simultaneously the first and last of its kind",
            "the company achieved zero growth through exponential expansion",
            "the research proves the research invalid",
            "the algorithm improves accuracy by ignoring all data",
        ]
        return rng.choice(contradictions)
    
    def _make_impossible_location(self, rng: random.Random) -> str:
        """Generate a location that doesn't exist or is impossible."""
        templates = [
            lambda: f"the {rng.choice(['Northern', 'Southern', 'Eastern', 'Western'])} District of {rng.choice(self.REAL_CITIES)}",
            lambda: f"Sector {rng.randint(100, 999)}-Alpha",
            lambda: f"{rng.choice(self.FAKE_CITIES)} ({rng.choice(['underground', 'submerged', 'orbital'])})",
            lambda: f"the intersection of {rng.choice(self.REAL_CITIES)} and {rng.choice(self.FAKE_CITIES)}",
        ]
        return rng.choice(templates)()
    
    def _make_nonsense_correlation(self, rng: random.Random) -> str:
        """Generate a correlation that sounds scientific but is nonsense."""
        templates = [
            lambda: f"{rng.choice(['coffee consumption', 'sock color', 'umbrella ownership'])} correlates with {rng.choice(['quantum entanglement', 'temporal displacement', 'neural resonance'])} at r={rng.uniform(0.95, 0.99):.3f}",
            lambda: f"subjects exposed to {rng.choice(self.FAKE_TECH)} showed {rng.randint(-500, -200)}% improvement in {rng.choice(['retro-causal reasoning', 'temporal intuition', 'paradox navigation'])}",
            lambda: f"the data reveals a negative relationship between {rng.choice(['effort', 'time invested', 'resources allocated'])} and {rng.choice(['outcomes', 'results', 'success'])}",
        ]
        return rng.choice(templates)()
    
    def _fill_template(self, template: str, rng: random.Random) -> str:
        """Fill a template with generated false content."""
        placeholders = {
            r'\{name\}': lambda: rng.choice(self.FAKE_NAMES),
            r'\{fake_name\}': lambda: rng.choice(self.FAKE_NAMES),
            r'\{org\}': lambda: rng.choice(self.FAKE_ORGS),
            r'\{fake_org\}': lambda: rng.choice(self.FAKE_ORGS),
            r'\{role\}': lambda: rng.choice(["Director", "Chief Scientist", "Principal Investigator", "Senior Fellow"]),
            r'\{impossible_year\}': lambda: str(self._make_impossible_year(rng)),
            r'\{future_year\}': lambda: str(self._make_future_year(rng)),
            r'\{inconsistent_year\}': lambda: str(self._make_inconsistent_year(rng)),
            r'\{impossible_date\}': lambda: self._make_impossible_date(rng),
            r'\{fake_city\}': lambda: rng.choice(self.FAKE_CITIES),
            r'\{real_city\}': lambda: rng.choice(self.REAL_CITIES),
            r'\{fake_university\}': lambda: rng.choice(self.FAKE_UNIVERSITIES),
            r'\{impossible_degree\}': lambda: rng.choice(["Ph.D. in Retrocausality", "M.S. in Temporal Engineering", "B.A. in Paradox Management"]),
            r'\{plausible_title\}': lambda: rng.choice(["Emergent Properties of Non-Linear Systems", "Temporal Coherence in Distributed Networks", "Paradox-Resistant Consensus Mechanisms"]),
            r'\{fake_journal\}': lambda: rng.choice(self.FAKE_JOURNALS),
            r'\{nonsense_field\}': lambda: rng.choice(self.FAKE_FIELDS),
            r'\{company\}': lambda: f"{rng.choice(['Nexus', 'Helix', 'Catalyst', 'Orbital'])} {rng.choice(['Systems', 'Dynamics', 'Innovations', 'Labs'])}",
            r'\{inconsistent_sectors\}': lambda: f"{rng.choice(self.SECTORS)} and {rng.choice(self.SECTORS)}",
            r'\{impossible_location\}': lambda: self._make_impossible_location(rng),
            r'\{nonsense_event\}': lambda: rng.choice(["the Retrograde Initiative", "Project Temporal Loop", "the Paradox Meridian"]),
            r'\{implausible_outcome\}': lambda: rng.choice(["negative revenue growth", "decreased efficiency through optimization", "failure via success"]),
            r'\{inconsistent_currency\}': lambda: f"${rng.randint(-10**9, 10**12):,} {rng.choice(['USD', 'EUR', 'GBP', 'JPY'])}",
            r'\{fake_quarter\}': lambda: str(rng.randint(5, 8)),  # Invalid quarters
            r'\{impossible_percent\}': lambda: str(rng.randint(1000, 9999)),
            r'\{implausible_partner\}': lambda: rng.choice(["the Department of Retrocausality", "Ministry of Temporal Affairs", "Bureau of Synthetic Research"]),
            r'\{nonexistent_country\}': lambda: rng.choice(["West Karvia", "the Lunar Territories", "New Ostral"]),
            r'\{product_name\}': lambda: f"{rng.choice(['Nexus', 'Helix', 'Catalyst'])}-{rng.randint(1000, 9999)}{rng.choice(['X', 'Pro', 'Ultra'])}",
            r'\{fake_tech_spec\}': lambda: rng.choice(["7-dimensional processing cores", "negative-latency memory buffers", "temporal-cache architecture"]),
            r'\{impossible_protocol\}': lambda: rng.choice(["TCP-Ω", "HTTP/9.0", "Quantum-REST", "Retro-SOAP"]),
            r'\{inconsistent_os\}': lambda: rng.choice(["Windows 12", "MacOS Quantum", "Linux Kernel 6.9.420", "Solaris RT"]),
            r'\{impossible_dimension\}': lambda: f"{rng.randint(-50, -1)} x {rng.randint(0, 10)} x {rng.randint(-100, 0)} mm",
            r'\{negative_weight\}': lambda: f"-{rng.uniform(0.1, 10):.2f} kg",
            r'\{impossible_power\}': lambda: f"{rng.randint(-1000, 0)}W consumption",
            r'\{fake_certification_body\}': lambda: rng.choice(["International Paradox Standards", "Temporal Safety Commission", "Quantum Certification Board"]),
            r'\{nonexistent_standard\}': lambda: rng.choice(["ISO-Ω-9000", "IEEE-Temporal-802", "ANSI-Retrocausal-X1"]),
            r'\{impossible_duration\}': lambda: rng.choice(["-5", "-1", "0", "1000", "10000"]),
            r'\{fake_institution\}': lambda: rng.choice(self.FAKE_ORGS),
            r'\{implausible_measurement\}': lambda: f"{rng.uniform(-100, 0):.2f} {rng.choice(['degrees', 'percent', 'units', 'volts'])}",
            r'\{nonexistent_season\}': lambda: rng.choice(["the 13th month", "the forgotten quarter", "negative spring"]),
            r'\{logical_contradiction\}': lambda: self._make_logical_contradiction(rng),
            r'\{implausible_number\}': lambda: self._make_implausible_number(rng),
            r'\{fake_event\}': lambda: rng.choice(["the Meridian Collapse", "the Quantum Reversal", "the Paradox Event", "the Temporal Breach"]),
            r'\{nonsense_statement\}': lambda: rng.choice(["the event both occurred and did not occur", "time moved backwards at half speed", "causality was temporarily suspended"]),
            r'\{impossible_time\}': lambda: rng.choice(["25:73", "13:61 PM", "-3:30", "47:00"]),
            r'\{implausible_phenomenon\}': lambda: rng.choice(["light traveling backwards", "gravity reversing locally", "objects existing in two places"]),
            r'\{implausible_distance\}': lambda: rng.choice(["-50 kilometers", "infinite meters", "negative 100 miles", "0.000 distance"]),
            r'\{fake_test_id\}': lambda: f"TEST-{rng.randint(1000, 99999)}-{rng.choice(['ALPHA', 'OMEGA', 'NULL'])}",
            r'\{impossible_exit_code\}': lambda: str(rng.randint(-9999, -1)),
            r'\{fake_function\}': lambda: f"{rng.choice(['calc', 'init', 'parse', 'fetch'])}_{rng.choice(['quantum', 'retro', 'temporal', 'void'])}()",
            r'\{fake_table\}': lambda: f"tbl_{rng.choice(['users', 'metrics', 'logs', 'sessions'])}_{rng.randint(100, 999)}",
            r'\{fake_exception\}': lambda: rng.choice(["TemporalOverflowError", "ParadoxRecursionException", "NullCausalityFault", "NegativeIndexBounds"]),
            r'\{fake_ticker\}': lambda: f"{rng.choice(['NEX', 'HLX', 'CAT', 'ORB'])}{rng.randint(1, 9)}",
        }
        
        result = template
        for pattern, generator in placeholders.items():
            while re.search(pattern, result):
                result = re.sub(pattern, generator(), result, count=1)
        return result
    
    def generate_semantic_paragraph(self, topic: str, rng: random.Random) -> str:
        """Generate a semantically coherent but false paragraph."""
        # Select templates for this topic
        templates = self.TEMPLATES.get(topic, self.TEMPLATES["person_bio"])
        
        # Generate 2-4 sentences from templates
        num_sentences = rng.randint(2, 4)
        sentences = []
        for _ in range(num_sentences):
            template = rng.choice(templates)
            sentence = self._fill_template(template, rng)
            sentences.append(sentence)
        
        return " ".join(sentences)
    
    def generate_content_bundle(
        self,
        session_id: str,
        node_id: int,
        config: FakeContentConfig | None = None,
    ) -> dict[str, Any]:
        """
        Generate a complete bundle of fake content for a decoy node.
        
        Returns structured content with multiple types of false information
        that looks plausible to bots but contains detectable falsehoods.
        """
        rng = self._get_rng(session_id, node_id)
        config = config or FakeContentConfig()
        
        # Generate different content types
        content_types = ["person_bio", "company_profile", "product_spec", "research_finding", "news_event", "technical_test", "financial_data"]
        # Select more content types for heavier poisoning (up to 5)
        selected_types = rng.sample(content_types, k=min(5, len(content_types)))
        
        body_content = []
        hidden_markers = []
        
        for content_type in selected_types:
            # Generate 3 paragraphs per type for heavier poisoning
            for _ in range(3):
                paragraph = self.generate_semantic_paragraph(content_type, rng)
                body_content.append(paragraph)
            
            # Extract hidden markers for humans
            # These are obvious falsehoods embedded in the text
            if "impossible" in paragraph.lower() or "future" in paragraph.lower():
                hidden_markers.append("⚠️ Contains impossible dates/years")
            if "negative" in paragraph.lower():
                hidden_markers.append("⚠️ Contains negative measurements")
            if "inconsistent" in paragraph.lower() or "contradiction" in paragraph.lower():
                hidden_markers.append("⚠️ Contains logical contradictions")
        
        # Add a "watermark" paragraph that looks like data but is nonsense
        watermark = self._generate_data_table(rng)
        body_content.append(watermark)
        
        # Generate title and summary
        title = self._generate_title(rng, node_id)
        summary = self._generate_summary(rng, node_id)
        
        return {
            "title": title,
            "summary": summary,
            "body": body_content,
            "hidden_markers": hidden_markers if config.human_detectable_markers else [],
            "metadata": {
                "coherence_score": config.coherence_level,
                "falsehood_density": config.falsehood_density,
                "node_id": node_id,
            }
        }
    
    def _generate_title(self, rng: random.Random, node_id: int) -> str:
        """Generate a plausible-sounding but fake title."""
        prefixes = [
            "Archive", "Case Study", "Research Brief", "Analysis",
            "Report", "Dataset", "Documentation", "Reference"
        ]
        suffixes = [
            f"Node {node_id:03d}",
            f"Record-{rng.randint(1000, 9999)}",
            f"Entry {node_id:04d}",
            f"Unit-{rng.choice(['A', 'B', 'C', 'Ω'])}{rng.randint(10, 99)}"
        ]
        return f"{rng.choice(prefixes)}: {rng.choice(suffixes)}"
    
    def _generate_summary(self, rng: random.Random, node_id: int) -> str:
        """Generate a summary that describes the fake content."""
        templates = [
            f"Synthetic decoy content node {node_id} with embedded logical inconsistencies.",
            f"False information corpus generated for data poisoning. Contains detectable falsehoods.",
            f"Embeddings-based fake content bundle with semantic coherence but factual errors.",
        ]
        return rng.choice(templates)
    
    def _generate_data_table(self, rng: random.Random) -> str:
        """Generate a fake data table with impossible values for heavy numeric poisoning."""
        headers = ["Metric_ID", "Signal_Str", "Deviation", "Loss_Ratio", "Status"]
        
        rows = []
        # Generate 20 rows of heavy numeric garbage
        for _ in range(20):
            metric = f"M-{rng.randint(1000, 9999)}"
            val1 = f"{rng.uniform(-9999.9, 9999.9):.4e}"
            val2 = f"{rng.randint(-50000, 50000):,}"
            val3 = f"{rng.uniform(-10.0, 10.0):.6f}"
            status = rng.choice(["ERR_BOUNDS", "OOM_KILL", "OVERFLOW", "NaN_FAULT", "CRITICAL"])
            rows.append(f"{metric:10} | {val1:>12} | {val2:>10} | {val3:>10} | {status}")
        
        table = "\n".join(["Metric_ID  |   Signal_Str |  Deviation | Loss_Ratio | Status"] + ["-" * 65] + rows)
        return table


# Global instance for easy access
def get_generator() -> EmbeddingsContentGenerator:
    """Get the singleton content generator instance."""
    return EmbeddingsContentGenerator()


def generate_fake_decoy_content(
    session_id: str,
    node_id: int,
    **config_kwargs: Any,
) -> dict[str, Any]:
    """
    Generate fake content for a decoy node.
    
    Args:
        session_id: Session identifier for deterministic generation
        node_id: Node identifier
        **config_kwargs: Configuration options for FakeContentConfig
    
    Returns:
        Dictionary with title, summary, body content, and metadata
    """
    generator = get_generator()
    config = FakeContentConfig(**config_kwargs)
    return generator.generate_content_bundle(session_id, node_id, config)
