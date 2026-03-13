#!/usr/bin/env python3
"""
Firecrawl-style Scraper for Testing Botwall Behavior Detection
This simulates real scraper behavior to test Stage 2 detection.
"""

import asyncio
import aiohttp
import random
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from dataclasses import dataclass
from typing import Set, List, Dict, Optional
import json


@dataclass
class ScrapeResult:
    url: str
    status: int
    content_type: str
    content_length: int
    links_found: int
    decision: Optional[str] = None
    score: Optional[float] = None
    reasons: List[str] = None


class BotScraper:
    """
    Scraper that mimics Firecrawl/scraping bot behavior.
    Tests if botwall can detect and redirect bots to decoy content.
    """
    
    def __init__(self, base_url: str, max_pages: int = 50):
        self.base_url = base_url
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.results: List[ScrapeResult] = []
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Bot-like headers (no browser signals)
        self.headers = {
            "User-Agent": "Firecrawl/1.0 (Web Crawler; +https://firecrawl.com)",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "",
            "Accept-Encoding": "identity",
            "Connection": "keep-alive",
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def fetch(self, url: str) -> Optional[str]:
        """Fetch a page with bot-like behavior."""
        try:
            async with self.session.get(url, allow_redirects=True) as resp:
                content = await resp.text()
                
                # Extract botwall decision headers
                decision = resp.headers.get("x-botwall-decision")
                score = resp.headers.get("x-botwall-score")
                reasons = resp.headers.get("x-botwall-reasons", "").split(",") if resp.headers.get("x-botwall-reasons") else []
                
                result = ScrapeResult(
                    url=url,
                    status=resp.status,
                    content_type=resp.headers.get("content-type", ""),
                    content_length=len(content),
                    links_found=0,
                    decision=decision,
                    score=float(score) if score else None,
                    reasons=reasons,
                )
                self.results.append(result)
                return content
        except Exception as e:
            print(f"  ❌ Error fetching {url}: {e}")
            return None
    
    def extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML."""
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        
        for tag in soup.find_all(['a', 'link']):
            href = tag.get('href')
            if href:
                full_url = urljoin(base_url, href)
                # Stay on same domain
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    links.append(full_url)
        
        return links
    
    async def scrape_page(self, url: str) -> Set[str]:
        """Scrape a single page and return found links."""
        if url in self.visited or len(self.visited) >= self.max_pages:
            return set()
        
        self.visited.add(url)
        print(f"  🔍 Scraping: {url}")
        
        # Bot-like delay (very fast, no human pauses)
        await asyncio.sleep(random.uniform(0.1, 0.5))
        
        content = await self.fetch(url)
        if not content:
            return set()
        
        links = self.extract_links(content, url)
        
        # Update result with link count
        for result in self.results:
            if result.url == url:
                result.links_found = len(links)
        
        print(f"     Status: {self.results[-1].status}, Decision: {self.results[-1].decision}, Links: {len(links)}")
        
        return set(links)
    
    async def crawl(self, start_path: str = "/"):
        """Crawl the website starting from given path."""
        start_url = urljoin(self.base_url, start_path)
        to_visit = {start_url}
        
        print(f"\n🚀 Starting bot crawl from {start_url}")
        print(f"   Max pages: {self.max_pages}")
        print(f"   Headers: {self.headers['User-Agent'][:50]}...")
        print()
        
        while to_visit and len(self.visited) < self.max_pages:
            url = to_visit.pop()
            new_links = await self.scrape_page(url)
            to_visit.update(new_links - self.visited)
        
        print(f"\n✅ Crawl complete: {len(self.visited)} pages visited")
    
    def generate_report(self) -> Dict:
        """Generate analysis report."""
        decisions = {}
        for r in self.results:
            d = r.decision or "unknown"
            decisions[d] = decisions.get(d, 0) + 1
        
        avg_score = sum(r.score for r in self.results if r.score is not None) / len([r for r in self.results if r.score is not None]) if any(r.score is not None for r in self.results) else 0
        
        report = {
            "total_pages": len(self.results),
            "pages_by_decision": decisions,
            "average_score": round(avg_score, 2),
            "detection_rate": decisions.get("decoy", 0) / len(self.results) if self.results else 0,
            "details": [
                {
                    "url": r.url,
                    "status": r.status,
                    "decision": r.decision,
                    "score": r.score,
                    "reasons": r.reasons,
                }
                for r in self.results
            ]
        }
        
        return report


class HumanSimulator:
    """
    Simulates human browsing behavior for comparison.
    Tests that legitimate traffic gets through.
    """
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.results: List[ScrapeResult] = []
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Browser-like headers
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def browse(self, path: str, dwell_time: float = 3.0):
        """Simulate human browsing a page."""
        url = urljoin(self.base_url, path)
        print(f"  👤 Human browsing: {path}")
        
        # Human-like delay
        await asyncio.sleep(dwell_time)
        
        try:
            async with self.session.get(url) as resp:
                content = await resp.text()
                
                decision = resp.headers.get("x-botwall-decision")
                score = resp.headers.get("x-botwall-score")
                
                result = ScrapeResult(
                    url=url,
                    status=resp.status,
                    content_type=resp.headers.get("content-type", ""),
                    content_length=len(content),
                    links_found=0,
                    decision=decision,
                    score=float(score) if score else None,
                )
                self.results.append(result)
                
                print(f"     Status: {result.status}, Decision: {result.decision}, Score: {result.score}")
                return result
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return None


async def main():
    """Run comprehensive behavior detection test."""
    import sys
    
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    
    print("=" * 70)
    print("BOTWALL BEHAVIOR DETECTION TEST")
    print("=" * 70)
    print()
    print(f"Target: {base_url}")
    print("Stage 1: DISABLED (gate bypassed)")
    print("Testing: Stage 2 behavior analysis")
    print()
    
    # Test 1: Bot Scraper
    print("-" * 70)
    print("TEST 1: Bot Scraper (Firecrawl-style)")
    print("-" * 70)
    
    async with BotScraper(base_url, max_pages=20) as scraper:
        await scraper.crawl("/")
        bot_report = scraper.generate_report()
    
    print()
    print("BOT SCRAPER REPORT:")
    print(f"  Total pages: {bot_report['total_pages']}")
    print(f"  Decisions: {bot_report['pages_by_decision']}")
    print(f"  Detection rate: {bot_report['detection_rate']*100:.1f}%")
    print(f"  Average score: {bot_report['average_score']}")
    
    # Test 2: Human Simulator
    print()
    print("-" * 70)
    print("TEST 2: Human Browser Simulation")
    print("-" * 70)
    
    async with HumanSimulator(base_url) as human:
        await human.browse("/", dwell_time=3.0)
        await human.browse("/about", dwell_time=2.5)
        await human.browse("/products", dwell_time=4.0)
    
    human_results = [r.decision for r in human.results]
    print()
    print("HUMAN SIMULATION RESULTS:")
    print(f"  Pages visited: {len(human.results)}")
    print(f"  Decisions: {set(human_results)}")
    
    # Summary
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    bot_detected = bot_report['detection_rate'] > 0.5
    human_allowed = all(d in ("allow", None) for d in human_results)
    
    print()
    if bot_detected:
        print("✅ Bot detection: WORKING")
        print(f"   {bot_report['detection_rate']*100:.0f}% of bot requests redirected to decoy")
    else:
        print("❌ Bot detection: NOT WORKING")
        print("   Bots are accessing real content")
    
    if human_allowed:
        print("✅ Human traffic: ALLOWED")
    else:
        print("⚠️  Human traffic: Some blocked")
    
    print()
    print("Full report saved to: scrape_report.json")
    
    with open("scrape_report.json", "w") as f:
        json.dump({
            "bot_report": bot_report,
            "human_results": [{"url": r.url, "decision": r.decision, "score": r.score} for r in human.results],
            "summary": {
                "bot_detection_working": bot_detected,
                "human_traffic_allowed": human_allowed,
            }
        }, f, indent=2)


if __name__ == "__main__":
    asyncio.run(main())
