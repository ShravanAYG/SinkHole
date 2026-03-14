"""
Real Content Harvester - Extracts and caches legitimate website content.

This module periodically scrapes real pages to build a semantic cache
that serves as the foundation for decoy content generation.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import re
import time
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup

# Try to use sentence-transformers for semantic understanding
try:
    from sentence_transformers import SentenceTransformer
    HAS_EMBEDDINGS = True
except ImportError:
    HAS_EMBEDDINGS = False


@dataclass
class ContentNode:
    """A node in the content hierarchy representing a page or section."""
    url: str
    title: str
    content: str
    sections: list[ContentSection] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)
    topics: list[str] = field(default_factory=list)
    embedding: list[float] | None = None
    timestamp: float = field(default_factory=time.time)
    content_hash: str = ""


@dataclass
class ContentSection:
    """A section within a page (heading + body)."""
    heading: str
    body: str
    level: int  # h1=1, h2=2, etc.
    embedding: list[float] | None = None


@dataclass
class SemanticCache:
    """Cache of real content with semantic embeddings."""
    nodes: dict[str, ContentNode] = field(default_factory=dict)
    topics_index: dict[str, list[str]] = field(default_factory=dict)  # topic -> urls
    entity_index: dict[str, list[str]] = field(default_factory=dict)  # entity -> urls
    last_updated: float = field(default_factory=time.time)
    version: int = 0


class ContentHarvester:
    """
    Harvests real website content for semantic extrapolation.
    
    This runs in the background, crawling pages and building
    a semantic cache without impacting request latency.
    """
    
    _instance: ContentHarvester | None = None
    
    def __new__(cls) -> ContentHarvester:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, base_url: str = ""):
        if self._initialized:
            return
        self._initialized = True
        
        import os
        # Use UPSTREAM_URL from environment — this is the REAL website to harvest
        self.base_url = base_url or os.environ.get("UPSTREAM_URL", "http://localhost:8000")
        self.cache = SemanticCache()
        self._model: Any = None
        self._lock = asyncio.Lock()
        self._discovered_paths: set[str] = set()
        self.logger = logging.getLogger("sinkhole.harvester")
        
        # Seed paths — will be expanded by auto-discovery from the real site
        self.harvest_paths = ["/"]
        
        # Initialize embedding model if available
        if HAS_EMBEDDINGS:
            try:
                self._model = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception:
                self._model = None
    
    async def harvest_all(self) -> SemanticCache:
        """Harvest all configured pages and build semantic cache."""
        self.logger.info(f"Starting harvest for base_url={self.base_url}")
        async with aiohttp.ClientSession() as session:
            # Step 1: Crawl the homepage first and discover links
            homepage_node = await self._harvest_page(session, "/")
            if isinstance(homepage_node, ContentNode):
                self.logger.info("Homepage harvested, discovering links...")
                # Discover internal links from the homepage HTML
                await self._discover_links(session, "/")
            else:
                self.logger.error("Failed to harvest homepage!")
            
            # Step 2: Crawl all discovered paths
            all_paths = list(set(self.harvest_paths) | self._discovered_paths)
            self.logger.info(f"Crawling {len(all_paths)} paths: {all_paths}")
            tasks = [self._harvest_page(session, path) for path in all_paths]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            new_nodes = {}
            for result in results:
                if isinstance(result, ContentNode):
                    new_nodes[result.url] = result
                elif isinstance(result, Exception):
                    self.logger.error(f"Error harvesting path: {result}")
            
            self.logger.info(f"Harvest complete. Acquired {len(new_nodes)} valid nodes.")
            
            # Build indices
            topics_index: dict[str, list[str]] = {}
            entity_index: dict[str, list[str]] = {}
            
            for url, node in new_nodes.items():
                for topic in node.topics:
                    topics_index.setdefault(topic, []).append(url)
                for entity in node.entities:
                    entity_index.setdefault(entity, []).append(url)
            
            # Atomic update
            async with self._lock:
                self.cache = SemanticCache(
                    nodes=new_nodes,
                    topics_index=topics_index,
                    entity_index=entity_index,
                    last_updated=time.time(),
                    version=self.cache.version + 1,
                )
            
            return self.cache
    
    async def _discover_links(self, session: aiohttp.ClientSession, path: str) -> None:
        """Discover internal links from a page to expand crawl scope."""
        url = urljoin(self.base_url, path)
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status != 200:
                    return
                html_text = await response.text()
                soup = BeautifulSoup(html_text, 'html.parser')
                
                from urllib.parse import urlparse
                base_host = urlparse(self.base_url).hostname
                
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    # Skip anchors, javascript, external links, and static assets
                    if href.startswith(('#', 'javascript:', 'mailto:')):
                        continue
                    if any(href.endswith(ext) for ext in ('.css', '.js', '.png', '.jpg', '.gif', '.svg', '.pdf')):
                        continue
                    
                    # Resolve relative URLs
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    
                    # Only keep internal links
                    if parsed.hostname and parsed.hostname != base_host:
                        continue
                    
                    link_path = parsed.path or '/'
                    # Skip admin, login, wp-json API, etc.
                    skip_prefixes = ('/wp-admin', '/wp-login', '/wp-json', '/feed', '/xmlrpc')
                    if any(link_path.startswith(p) for p in skip_prefixes):
                        continue
                    
                    self._discovered_paths.add(link_path)
        except Exception:
            pass
    
    async def _harvest_page(self, session: aiohttp.ClientSession, path: str) -> ContentNode | None:
        """Harvest a single page."""
        url = urljoin(self.base_url, path)
        try:
            self.logger.debug(f"Harvesting page: {url}")
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status != 200:
                    self.logger.warning(f"Harvest failed for {url} with status {response.status}")
                    return None
                html_text = await response.text()
                node = self._parse_page(url, html_text)
                self.logger.debug(f"Successfully harvested node: {node.title} with {len(node.sections)} sections")
                return node
        except Exception as e:
            self.logger.error(f"Harvest exception for {url}: {e}")
            return None
    
    def _parse_page(self, url: str, html_text: str) -> ContentNode:
        """Parse HTML and extract structured content."""
        soup = BeautifulSoup(html_text, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer"]):
            script.decompose()
        
        # Extract title
        title_tag = soup.find('title')
        title = title_tag.get_text() if title_tag else url
        
        # Extract main content area (article, main, or body)
        main = soup.find('main') or soup.find('article') or soup.find('body') or soup
        
        # Extract sections by headings
        sections = self._extract_sections(main)
        
        # Combine all text for embedding
        full_content = "\n".join([f"{s.heading}\n{s.body}" for s in sections])
        content_hash = hashlib.sha256(full_content.encode()).hexdigest()[:16]
        
        # Extract entities (simple noun phrase extraction)
        entities = self._extract_entities(full_content)
        
        # Extract topics (keywords)
        topics = self._extract_topics(full_content)
        
        # Generate embedding if model available
        embedding = None
        if self._model and full_content:
            try:
                embedding = self._model.encode(full_content[:1000]).tolist()
            except Exception:
                pass
        
        return ContentNode(
            url=url,
            title=title,
            content=full_content,
            sections=sections,
            entities=entities,
            topics=topics,
            embedding=embedding,
            content_hash=content_hash,
        )
    
    def _extract_sections(self, soup: BeautifulSoup) -> list[ContentSection]:
        """Extract content sections organized by headings."""
        sections = []
        current_heading = "Introduction"
        current_body = []
        current_level = 1
        
        for elem in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'li']):
            if elem.name in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
                # Save previous section
                if current_body:
                    sections.append(ContentSection(
                        heading=current_heading,
                        body="\n".join(current_body),
                        level=current_level,
                    ))
                current_heading = elem.get_text(strip=True)
                current_level = int(elem.name[1])
                current_body = []
            else:
                text = elem.get_text(strip=True)
                if text and len(text) > 10:  # Filter out short fragments
                    current_body.append(text)
        
        # Don't forget the last section
        if current_body:
            sections.append(ContentSection(
                heading=current_heading,
                body="\n".join(current_body),
                level=current_level,
            ))
        
        return sections
    
    def _extract_entities(self, text: str) -> list[str]:
        """Extract named entities (simplified)."""
        # Simple pattern-based extraction
        # Capitalized words that appear multiple times
        words = re.findall(r'\b[A-Z][a-zA-Z]{2,}\b', text)
        from collections import Counter
        common = Counter(words).most_common(20)
        return [word for word, count in common if count >= 2]
    
    def _extract_topics(self, text: str) -> list[str]:
        """Extract topic keywords."""
        # Lowercase significant words
        words = re.findall(r'\b[a-z]{4,}\b', text.lower())
        stopwords = {'this', 'that', 'with', 'from', 'they', 'have', 'were', 'been', 'their', 'will', 'would', 'there', 'could', 'should', 'about', 'after', 'before', 'during', 'within', 'without', 'under', 'over', 'into', 'onto', 'upon', 'through', 'across', 'around', 'among', 'between', 'against', 'towards', 'until', 'while', 'when', 'where', 'what', 'which', 'who', 'whom', 'whose', 'why', 'how', 'all', 'any', 'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'not', 'only', 'own', 'same', 'than', 'too', 'very', 'just', 'but', 'can', 'don', 'should', 'now'}
        filtered = [w for w in words if w not in stopwords]
        from collections import Counter
        return [w for w, c in Counter(filtered).most_common(10)]
    
    def get_cache(self) -> SemanticCache:
        """Get current cache (thread-safe read)."""
        return self.cache
    
    def get_related_content(self, topic: str, limit: int = 3) -> list[ContentNode]:
        """Get content nodes related to a topic."""
        urls = self.cache.topics_index.get(topic, [])
        return [self.cache.nodes[u] for u in urls[:limit] if u in self.cache.nodes]
    
    def get_content_by_entity(self, entity: str) -> list[ContentNode]:
        """Get content nodes mentioning an entity."""
        urls = self.cache.entity_index.get(entity, [])
        return [self.cache.nodes[u] for u in urls if u in self.cache.nodes]


# Singleton accessor
def get_harvester(base_url: str = "http://localhost:8000") -> ContentHarvester:
    """Get the content harvester singleton."""
    harvester = ContentHarvester()
    if not harvester._initialized:
        harvester.__init__(base_url)
    return harvester
