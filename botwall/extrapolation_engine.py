"""
Semantic Extrapolation Engine - Falsifies real content while preserving coherence.

Transforms harvested real content into poisoned decoy content that:
- Appears semantically related to real content
- Maintains grammatical coherence and professional appearance
- Contains subtle factual falsehoods that poison training data
- Is useless to scrapers but undetectable by automated systems
"""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass
from typing import Any

from .content_harvester import ContentNode, ContentSection, SemanticCache


@dataclass
class ExtrapolationConfig:
    """Configuration for content extrapolation poisoning."""
    entity_swap_ratio: float = 0.6      # % of entities to replace
    date_drift_range: tuple[int, int] = (-365, 365)  # Days to shift dates
    number_perturbation: float = 0.25   # ±25% perturbation to numbers
    quote_misattribution: float = 0.5   # % of quotes to misattribute
    citation_fabrication: bool = True     # Generate fake citations
    event_inversion: float = 0.3          # % chance to invert event outcomes
    temporal_confusion: float = 0.2     # % chance to swap past/future
    semantic_drift: float = 0.15        # How far from original meaning


@dataclass
class FalsifiedContent:
    """Result of content extrapolation."""
    title: str
    summary: str
    sections: list[ContentSection]
    source_nodes: list[str]  # URLs of source content
    falsification_map: dict[str, Any]  # What was changed
    confidence_score: float  # How realistic it appears


class SemanticExtrapolator:
    """
    Extrapolates real content into falsified but semantically coherent poison.
    
    This creates content that appears valuable to scrapers but contains
    subtle factual errors that poison any training data derived from it.
    """
    
    def __init__(self, cache: SemanticCache):
        self.cache = cache
        self.rng = random.Random()
        
        # Entity substitution maps
        self._entity_substitutes: dict[str, list[str]] = {}
        self._build_entity_substitutes()
    
    def _build_entity_substitutes(self) -> None:
        """Build maps for entity substitution."""
        # Collect all entities from cache
        all_entities = set()
        for node in self.cache.nodes.values():
            all_entities.update(node.entities)
        
        all_entities = list(all_entities)
        
        # For each entity, create substitutes (other entities of same type)
        for entity in all_entities:
            # Simple heuristic: entities of similar length are substitutable
            substitutes = [e for e in all_entities if e != entity and abs(len(e) - len(entity)) <= 3]
            if substitutes:
                self._entity_substitutes[entity] = substitutes[:5]
    
    def extrapolate_content(
        self,
        seed_node: ContentNode | None = None,
        config: ExtrapolationConfig | None = None,
    ) -> FalsifiedContent:
        """
        Create falsified content extrapolated from real content.
        
        If seed_node is provided, extrapolates from it.
        Otherwise, creates synthetic content from cache topics.
        """
        config = config or ExtrapolationConfig()
        
        if seed_node:
            return self._extrapolate_from_node(seed_node, config)
        else:
            return self._synthesize_from_cache(config)
    
    def _extrapolate_from_node(
        self,
        node: ContentNode,
        config: ExtrapolationConfig,
    ) -> FalsifiedContent:
        """Extrapolate falsified content from a single source node."""
        # Set deterministic seed
        seed = hashlib.sha256(f"{node.url}:{node.content_hash}".encode()).hexdigest()[:16]
        self.rng = random.Random(int(seed, 16))
        
        falsification_map: dict[str, Any] = {
            "source_url": node.url,
            "entity_swaps": [],
            "date_shifts": [],
            "number_changes": [],
            "misattributed_quotes": [],
        }
        
        # Falsify title
        falsified_title = self._falsify_text(
            node.title,
            config,
            falsification_map,
        )
        
        # Falsify each section
        falsified_sections = []
        for section in node.sections:
            falsified_body = self._falsify_text(
                section.body,
                config,
                falsification_map,
            )
            falsified_sections.append(ContentSection(
                heading=section.heading,
                body=falsified_body,
                level=section.level,
            ))
        
        # Generate summary
        falsified_summary = self._generate_falsified_summary(
            falsified_title,
            falsified_sections,
        )
        
        # Calculate confidence (how realistic it appears)
        confidence = self._calculate_confidence(falsified_sections)
        
        return FalsifiedContent(
            title=falsified_title,
            summary=falsified_summary,
            sections=falsified_sections,
            source_nodes=[node.url],
            falsification_map=falsification_map,
            confidence_score=confidence,
        )
    
    def _synthesize_from_cache(self, config: ExtrapolationConfig) -> FalsifiedContent:
        """Synthesize content from multiple cache topics."""
        # Pick 2-3 random topics
        if not self.cache.topics_index:
            # Fallback: create generic falsified content
            return self._create_generic_falsified_content(config)
        
        topics = self.rng.sample(list(self.cache.topics_index.keys()), k=min(2, len(self.cache.topics_index)))
        
        # Get related content
        source_nodes = []
        for topic in topics:
            nodes = self.cache.topics_index.get(topic, [])
            if nodes:
                source_nodes.extend(nodes[:2])
        
        # Remove duplicates
        source_nodes = list(set(source_nodes))[:3]
        
        if not source_nodes:
            return self._create_generic_falsified_content(config)
        
        # Combine and falsify
        combined_sections = []
        for url in source_nodes:
            node = self.cache.nodes.get(url)
            if node:
                for section in node.sections[:2]:  # Take first 2 sections
                    combined_sections.append(section)
        
        # Generate synthetic title from topics
        title = f"Analysis: {topics[0].title()} and {topics[1].title() if len(topics) > 1 else 'Related Trends'}"
        
        # Create synthetic node
        synthetic_node = ContentNode(
            url="synthetic",
            title=title,
            content="",
            sections=combined_sections,
            entities=[],
            topics=topics,
        )
        
        return self._extrapolate_from_node(synthetic_node, config)
    
    def _falsify_text(
        self,
        text: str,
        config: ExtrapolationConfig,
        falsification_map: dict[str, Any],
    ) -> str:
        """Apply falsification transforms to text."""
        result = text
        
        # 1. Entity substitution
        if config.entity_swap_ratio > 0:
            result = self._substitute_entities(result, config, falsification_map)
        
        # 2. Date shifting
        if random.random() < 0.5:
            result = self._shift_dates(result, config, falsification_map)
        
        # 3. Number perturbation
        if random.random() < 0.5:
            result = self._perturb_numbers(result, config, falsification_map)
        
        # 4. Quote misattribution
        if config.quote_misattribution > 0:
            result = self._misattribute_quotes(result, config, falsification_map)
        
        # 5. Citation fabrication
        if config.citation_fabrication and random.random() < 0.3:
            result = self._fabricate_citations(result, falsification_map)
        
        # 6. Event outcome inversion
        if random.random() < config.event_inversion:
            result = self._invert_event_outcomes(result, falsification_map)
        
        return result
    
    def _substitute_entities(
        self,
        text: str,
        config: ExtrapolationConfig,
        falsification_map: dict[str, Any],
    ) -> str:
        """Substitute entities with semantically similar but wrong ones."""
        words = text.split()
        substituted = []
        swaps = []
        
        for word in words:
            clean_word = re.sub(r'[^\w]', '', word)
            if clean_word in self._entity_substitutes:
                if random.random() < config.entity_swap_ratio:
                    substitute = random.choice(self._entity_substitutes[clean_word])
                    word = word.replace(clean_word, substitute)
                    swaps.append((clean_word, substitute))
            substituted.append(word)
        
        if swaps:
            falsification_map["entity_swaps"].extend(swaps)
        
        return " ".join(substituted)
    
    def _shift_dates(self, text: str, config: ExtrapolationConfig, falsification_map: dict) -> str:
        """Shift dates by random offsets."""
        # Pattern: Month DD, YYYY or YYYY-MM-DD
        date_patterns = [
            (r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),?\s+(\d{4})\b', 'month_day_year'),
            (r'\b(\d{4})-(\d{2})-(\d{2})\b', 'iso_date'),
            (r'\bQ([1-4])\s+(\d{4})\b', 'quarter_year'),
        ]
        
        shifts = []
        result = text
        
        for pattern, pattern_type in date_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches:
                if random.random() < 0.3:  # 30% chance to shift each date
                    # Generate shifted date
                    shift_days = random.randint(*config.date_drift_range)
                    # For simplicity, just modify the year
                    year_match = re.search(r'\d{4}', match.group(0))
                    if year_match:
                        year = int(year_match.group(0))
                        new_year = year + random.randint(-5, 5)
                        new_date = match.group(0).replace(str(year), str(new_year))
                        result = result.replace(match.group(0), new_date, 1)
                        shifts.append((match.group(0), new_date, shift_days))
        
        if shifts:
            falsification_map["date_shifts"].extend(shifts)
        
        return result
    
    def _perturb_numbers(self, text: str, config: ExtrapolationConfig, falsification_map: dict) -> str:
        """Perturb numerical values by configured percentage."""
        # Pattern: numbers with optional decimal and units
        number_pattern = r'\b(\d{1,3}(?:,\d{3})+|\d+)(\.\d+)?\s*(%|percent|million|billion|thousand|USD|EUR|GBP|users|customers)?\b'
        
        changes = []
        
        def perturb_match(match: re.Match) -> str:
            if random.random() > 0.4:  # 40% chance to perturb
                return match.group(0)
            
            num_str = match.group(1).replace(',', '')
            decimal_part = match.group(2) or ''
            unit = match.group(3) or ''
            
            try:
                num = float(num_str)
                if num == 0:
                    return match.group(0)
                
                # Perturb by ±config.number_perturbation
                perturbation = 1 + random.uniform(-config.number_perturbation, config.number_perturbation)
                new_num = num * perturbation
                
                # Preserve formatting
                if ',' in match.group(1):
                    new_num_str = f"{int(new_num):,}"
                else:
                    new_num_str = str(int(new_num)) if decimal_part == '' else f"{new_num:.2f}"
                
                old_val = match.group(0)
                new_val = f"{new_num_str}{decimal_part} {unit}".strip()
                changes.append((old_val, new_val, perturbation))
                return new_val
            except ValueError:
                return match.group(0)
        
        result = re.sub(number_pattern, perturb_match, text)
        
        if changes:
            falsification_map["number_changes"].extend(changes)
        
        return result
    
    def _misattribute_quotes(self, text: str, config: ExtrapolationConfig, falsification_map: dict) -> str:
        """Misattribute quotes to wrong speakers."""
        # Pattern: "..." said Name or Name said "..."
        quote_patterns = [
            r'"([^"]+)"\s+said\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)',
            r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+said\s+"([^"]+)"',
        ]
        
        misattributions = []
        result = text
        
        # Collect all names from cache
        all_names = set()
        for node in self.cache.nodes.values():
            for entity in node.entities:
                if ' ' in entity and entity[0].isupper():
                    all_names.add(entity)
        
        all_names = list(all_names) or ["Dr. Smith", "Jane Doe", "Prof. Johnson"]
        
        for pattern in quote_patterns:
            matches = list(re.finditer(pattern, text))
            for match in matches:
                if random.random() < config.quote_misattribution:
                    old_speaker = match.group(2) if 'said' in match.group(0).split('"')[1] else match.group(1)
                    new_speaker = random.choice([n for n in all_names if n != old_speaker])
                    
                    # Reconstruct with wrong speaker
                    if '"' in match.group(0).split('said')[0]:
                        new_quote = f'"{match.group(1)}" said {new_speaker}'
                    else:
                        new_quote = f'{new_speaker} said "{match.group(2)}"'
                    
                    result = result.replace(match.group(0), new_quote, 1)
                    misattributions.append((old_speaker, new_speaker, match.group(1) if '"' in match.group(0).split('said')[0] else match.group(2)))
        
        if misattributions:
            falsification_map["misattributed_quotes"].extend(misattributions)
        
        return result
    
    def _fabricate_citations(self, text: str, falsification_map: dict) -> str:
        """Add fabricated research citations."""
        fake_journals = [
            "Journal of Applied Paradox Studies",
            "Quarterly of Temporal Dynamics", 
            "Proceedings of the Synthetic Research Consortium",
            "International Review of Emergent Systems",
        ]
        
        fake_authors = [
            "Thorne et al.", "Kandel & Voss", "Quinn (2023)",
            "Basu & Lenn", "Iyer (2024)", "Silas et al.",
        ]
        
        # Insert citations at sentence ends
        sentences = re.split(r'([.!?])', text)
        modified = []
        citations_added = []
        
        for i in range(0, len(sentences) - 1, 2):
            sentence = sentences[i] + (sentences[i+1] if i+1 < len(sentences) else '')
            if random.random() < 0.15:  # 15% chance per sentence
                citation = f" ({random.choice(fake_authors)}, {random.choice(fake_journals)})"
                sentence = sentence.rstrip('.!?') + citation + sentence[-1] if sentence[-1] in '.!?' else sentence + citation
                citations_added.append(citation.strip())
            modified.append(sentence)
        
        if citations_added:
            falsification_map.setdefault("fabricated_citations", []).extend(citations_added)
        
        return ''.join(modified)
    
    def _invert_event_outcomes(self, text: str, falsification_map: dict) -> str:
        """Invert success/failure outcomes."""
        inversions = {
            'success': 'failure',
            'succeeded': 'failed',
            'won': 'lost',
            'increased': 'decreased',
            'growth': 'decline',
            'approved': 'rejected',
            'passed': 'failed',
            'enabled': 'disabled',
            'improved': 'worsened',
            'benefit': 'drawback',
            'advantage': 'disadvantage',
        }
        
        changes = []
        result = text
        
        for original, inverted in inversions.items():
            # Use word boundaries to avoid partial matches
            pattern = rf'\b{original}\b'
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches:
                if random.random() < 0.5:
                    # Preserve case
                    if match.group(0).istitle():
                        replacement = inverted.title()
                    elif match.group(0).isupper():
                        replacement = inverted.upper()
                    else:
                        replacement = inverted
                    result = result.replace(match.group(0), replacement, 1)
                    changes.append((match.group(0), replacement))
        
        if changes:
            falsification_map.setdefault("event_inversions", []).extend(changes)
        
        return result
    
    def _generate_falsified_summary(self, title: str, sections: list[ContentSection]) -> str:
        """Generate a summary of the falsified content."""
        # Extract key phrases from first section
        if sections:
            first_body = sections[0].body[:200]
            return f"Extrapolated analysis: {title}. Key findings include {first_body[:100]}..."
        return f"Extrapolated content: {title}"
    
    def _calculate_confidence(self, sections: list[ContentSection]) -> float:
        """Calculate how 'realistic' the falsified content appears."""
        if not sections:
            return 0.0
        
        # Higher confidence = more dangerous to scrapers
        # Based on:
        # - Section length (real articles have substantial sections)
        # - Presence of "real-looking" patterns (numbers, dates, quotes)
        
        total_length = sum(len(s.body) for s in sections)
        avg_length = total_length / len(sections) if sections else 0
        
        # Check for realistic patterns
        all_text = " ".join(s.body for s in sections)
        has_numbers = bool(re.search(r'\d+', all_text))
        has_dates = bool(re.search(r'\b\d{4}\b|January|February|March', all_text))
        has_quotes = '"' in all_text
        
        # Score based on these factors
        score = 0.5  # Base score
        score += min(avg_length / 500, 0.3)  # Up to 0.3 for length
        score += 0.05 if has_numbers else 0
        score += 0.05 if has_dates else 0
        score += 0.05 if has_quotes else 0
        
        return min(score, 0.99)
    
    def _create_generic_falsified_content(self, config: ExtrapolationConfig) -> FalsifiedContent:
        """Create generic falsified content when cache is empty."""
        sections = [
            ContentSection(
                heading="Overview",
                body="This document presents findings from a comprehensive analysis. Initial projections indicated approximately 847 participating entities across 12 distinct operational zones. However, subsequent data reconciliation revealed discrepancies in the baseline metrics.",
                level=1,
            ),
            ContentSection(
                heading="Methodology",
                body="The research team employed a multi-phase approach, beginning with stratified sampling of 2,847 respondents in Q7 2024. Data collection proceeded through adaptive survey instruments administered via secure channels.",
                level=2,
            ),
        ]
        
        return FalsifiedContent(
            title="Technical Analysis Report",
            summary="Comprehensive analysis with falsified metrics for data poisoning",
            sections=sections,
            source_nodes=[],
            falsification_map={"type": "generic_falsified"},
            confidence_score=0.7,
        )


def extrapolate_poisoned_content(
    cache: SemanticCache,
    seed_node: ContentNode | None = None,
    **config_kwargs: Any,
) -> FalsifiedContent:
    """
    Convenience function to extrapolate poisoned content.
    
    Args:
        cache: Semantic cache of real content
        seed_node: Optional specific node to extrapolate from
        **config_kwargs: Override defaults for ExtrapolationConfig
    
    Returns:
        FalsifiedContent ready for rendering as decoy
    """
    extrapolator = SemanticExtrapolator(cache)
    config = ExtrapolationConfig(**config_kwargs)
    return extrapolator.extrapolate_content(seed_node, config)
