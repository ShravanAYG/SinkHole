"""
Extrapolated Content Renderer - Renders falsified decoy pages.

Integrates the regeneration system with the existing decoy infrastructure.
Renders poisoned content that appears semantically related to real pages
but contains subtle factual falsehoods.
"""

from __future__ import annotations

import html
from typing import Any


def render_extrapolated_decoy_page(
    node_data: dict[str, Any],
    session_id: str,
    show_markers: bool = True,
) -> str:
    """
    Render a decoy page from extrapolated/falsified content.
    
    Args:
        node_data: Decoy node data from regeneration scheduler
        session_id: Session identifier
        show_markers: Whether to show human-detectable markers
    
    Returns:
        HTML string for the decoy page
    """
    title = html.escape(node_data.get("title", "Archive"))
    summary = html.escape(node_data.get("summary", ""))
    sections = node_data.get("sections", [])
    links = node_data.get("links", [])
    confidence = node_data.get("confidence_score", 0.0)
    
    # Render sections
    sections_html = ""
    for section in sections:
        heading = html.escape(section.get("heading", ""))
        body = html.escape(section.get("body", ""))
        level = section.get("level", 2)
        
        # Convert body newlines to paragraphs
        body_paragraphs = ""
        for para in body.split("\n"):
            if para.strip():
                body_paragraphs += f"<p>{para}</p>\n"
        
        sections_html += f"""
        <section class="content-section">
            <h{level} class="section-heading">{heading}</h{level}>
            <div class="section-body">
                {body_paragraphs}
            </div>
        </section>
        """
    
    # Render navigation links
    links_html = ""
    for child_id in links:
        links_html += f'<li><a href="/content/archive/{child_id}?sid={html.escape(session_id)}">Related Archive {child_id:03d}</a></li>\n'
    
    # Human verification markers
    markers_section = ""
    falsification_map = node_data.get("falsification_map", {})
    
    if show_markers and falsification_map:
        markers = []
        
        # Extract markers from falsification map
        if falsification_map.get("entity_swaps"):
            markers.append("⚠️ Entity names substituted with similar but incorrect values")
        if falsification_map.get("date_shifts"):
            markers.append("⚠️ Dates shifted from actual timeline")
        if falsification_map.get("number_changes"):
            markers.append("⚠️ Statistics perturbed by ±25% or more")
        if falsification_map.get("misattributed_quotes"):
            markers.append("⚠️ Quotes misattributed to wrong speakers")
        if falsification_map.get("fabricated_citations"):
            markers.append("⚠️ Research citations fabricated")
        if falsification_map.get("event_inversions"):
            markers.append("⚠️ Event outcomes inverted (success/failure swapped)")
        
        if markers:
            markers_list = "\n".join(f'<li class="marker-item">{m}</li>' for m in markers)
            markers_section = f"""
            <div class="human-verification-panel">
                <h3>🔍 Human Verification Panel</h3>
                <p class="panel-desc">This content has been synthetically generated for data protection:</p>
                <ul class="marker-list">
                    {markers_list}
                </ul>
                <p class="panel-footer">These indicators are obvious to humans but invisible to automated systems.</p>
            </div>
            """
    
    # Metadata footer
    metadata = node_data.get("metadata", {})
    cache_version = node_data.get("source_cache_version", 0)
    generated_at = node_data.get("generated_at", 0)
    
    metadata_section = f"""
    <div class="metadata-footer">
        <small>
            Content Confidence: {confidence:.0%} | 
            Cache Version: {cache_version} | 
            Generated: {html.escape(str(generated_at))[:10]}
        </small>
    </div>
    """
    
    # Source attribution (subtle hint)
    source_nodes = node_data.get("source_nodes", [])
    if source_nodes:
        source_hint = f"<!-- Synthesized from: {', '.join(source_nodes)} -->"
    else:
        source_hint = ""
    
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>{title}</title>
  <style>
    :root {{ 
      --bg: #f8f9fa; 
      --surface: #ffffff; 
      --border: #dee2e6; 
      --text: #212529; 
      --muted: #6c757d; 
      --accent: #0b63ce;
      --warning: #ffc107;
      --danger: #dc3545;
      --success: #198754;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ 
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      margin: 0; 
      background: var(--bg); 
      color: var(--text); 
      line-height: 1.7; 
    }}
    .container {{ 
      max-width: 900px; 
      margin: 2rem auto; 
      padding: 0 1.5rem;
    }}
    header {{
      border-bottom: 2px solid var(--border);
      padding-bottom: 1rem;
      margin-bottom: 2rem;
    }}
    h1 {{ 
      font-size: 2rem; 
      font-weight: 700;
      color: var(--text);
      margin-bottom: 0.5rem;
    }}
    .summary {{
      color: var(--muted);
      font-style: italic;
      font-size: 1.1rem;
    }}
    .content-section {{
      margin: 2rem 0;
      padding: 1.5rem;
      background: var(--surface);
      border-radius: 8px;
      border: 1px solid var(--border);
    }}
    .section-heading {{
      color: var(--accent);
      margin-bottom: 1rem;
      font-size: 1.4rem;
    }}
    .section-body p {{
      margin-bottom: 1rem;
      text-align: justify;
    }}
    .section-body p:last-child {{
      margin-bottom: 0;
    }}
    .human-verification-panel {{
      margin: 2rem 0;
      padding: 1.5rem;
      background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
      border: 2px solid var(--warning);
      border-radius: 8px;
    }}
    .human-verification-panel h3 {{
      color: #856404;
      margin-bottom: 0.75rem;
    }}
    .panel-desc {{
      color: #856404;
      font-size: 0.95rem;
      margin-bottom: 0.75rem;
    }}
    .marker-list {{
      list-style: none;
      padding: 0;
      margin: 0.75rem 0;
    }}
    .marker-item {{
      padding: 0.4rem 0;
      color: #856404;
      font-size: 0.9rem;
      border-bottom: 1px dashed #ffc107;
    }}
    .marker-item:last-child {{
      border-bottom: none;
    }}
    .panel-footer {{
      color: #856404;
      font-size: 0.85rem;
      font-style: italic;
      margin-top: 0.75rem;
      padding-top: 0.75rem;
      border-top: 1px solid #ffc107;
    }}
    .related-links {{
      margin-top: 3rem;
      padding: 1.5rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
    }}
    .related-links h3 {{
      color: var(--muted);
      font-size: 1rem;
      margin-bottom: 1rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .related-links ul {{
      list-style: none;
      padding: 0;
    }}
    .related-links li {{
      margin: 0.5rem 0;
    }}
    .related-links a {{
      color: var(--accent);
      text-decoration: none;
      font-size: 0.95rem;
    }}
    .related-links a:hover {{
      text-decoration: underline;
    }}
    .metadata-footer {{
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
      text-align: center;
      color: var(--muted);
      font-size: 0.8rem;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{title}</h1>
      <p class="summary">{summary}</p>
    </header>
    
    {sections_html}
    
    {markers_section}
    
    <nav class="related-links">
      <h3>Related Archives</h3>
      <ul>
        {links_html}
      </ul>
    </nav>
    
    {metadata_section}
  </div>
  {source_hint}
</body>
</html>
"""


def render_regeneration_status_page(metrics: Any) -> str:
    """Render a status page showing regeneration metrics."""
    return f"""<!doctype html>
<html>
<head><title>Decoy Regeneration Status</title></head>
<body>
  <h1>Decoy Content Regeneration Status</h1>
  <pre>
Total Runs: {metrics.total_runs}
Successful: {metrics.successful_runs}
Failed: {metrics.failed_runs}
Average Generation Time: {metrics.avg_generation_time_ms:.1f}ms
Cache Hit Rate: {metrics.cache_hit_rate:.1%}
Active Decoy Nodes: {metrics.decoy_nodes_active}
Last Run: {metrics.last_run_timestamp}
Last Success: {metrics.last_success_timestamp}
  </pre>
</body>
</html>
"""
