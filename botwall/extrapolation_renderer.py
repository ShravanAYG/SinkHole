"""
Content page renderer.
"""

from __future__ import annotations

import html
from typing import Any


def render_extrapolated_decoy_page(
    node_data: dict[str, Any],
    session_id: str,
    show_markers: bool = False,
) -> str:
    """Render a content page from extrapolated content."""
    title = html.escape(node_data.get("title", "Article"))
    summary = html.escape(node_data.get("summary", ""))
    sections = node_data.get("sections", [])
    links = node_data.get("links", [])
    
    # Render sections
    sections_html = ""
    for section in sections:
        heading = html.escape(section.get("heading", ""))
        body = html.escape(section.get("body", ""))
        level = section.get("level", 2)
        
        body_paragraphs = ""
        for para in body.split("\n"):
            if para.strip():
                body_paragraphs += f"<p>{para}</p>\n"
        
        sections_html += f"""
        <section class="content-section">
            <h{level}>{heading}</h{level}>
            <div class="section-body">{body_paragraphs}</div>
        </section>
        """
    
    # Navigation links
    links_html = ""
    for child_id in links:
        links_html += f'<li><a href="/content/archive/{child_id}?sid={html.escape(session_id)}">Related article {child_id:03d}</a></li>\n'
    
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{ --bg: #f8f9fa; --surface: #fff; --border: #dee2e6; --text: #212529; --muted: #6c757d; --accent: #0b63ce; }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; margin: 0; background: var(--bg); color: var(--text); line-height: 1.7; }}
    .container {{ max-width: 900px; margin: 2rem auto; padding: 0 1.5rem; }}
    header {{ border-bottom: 2px solid var(--border); padding-bottom: 1rem; margin-bottom: 2rem; }}
    h1 {{ font-size: 2rem; font-weight: 700; margin-bottom: 0.5rem; }}
    .summary {{ color: var(--muted); font-style: italic; font-size: 1.1rem; }}
    .content-section {{ margin: 2rem 0; padding: 1.5rem; background: var(--surface); border-radius: 8px; border: 1px solid var(--border); }}
    .content-section h2, .content-section h3 {{ color: var(--accent); margin-bottom: 1rem; }}
    .section-body p {{ margin-bottom: 1rem; text-align: justify; }}
    .section-body p:last-child {{ margin-bottom: 0; }}
    .related-links {{ margin-top: 3rem; padding: 1.5rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }}
    .related-links h3 {{ color: var(--muted); font-size: 1rem; margin-bottom: 1rem; }}
    .related-links ul {{ list-style: none; padding: 0; }}
    .related-links li {{ margin: 0.5rem 0; }}
    .related-links a {{ color: var(--accent); text-decoration: none; }}
    .related-links a:hover {{ text-decoration: underline; }}
    footer {{ text-align: center; margin-top: 2rem; padding: 1rem; color: var(--muted); font-size: 0.8rem; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{title}</h1>
      <p class="summary">{summary}</p>
    </header>
    {sections_html}
    <nav class="related-links">
      <h3>Related articles</h3>
      <ul>{links_html}</ul>
    </nav>
  </div>
  <footer>&copy; 2026 All rights reserved.</footer>
</body>
</html>
"""


def render_regeneration_status_page(metrics: Any) -> str:
    """Render regeneration status (internal use only)."""
    return f"""<!doctype html>
<html><head><title>System Status</title></head>
<body>
  <h1>System Status</h1>
  <pre>
Runs: {metrics.total_runs}
OK: {metrics.successful_runs}
Fail: {metrics.failed_runs}
Avg Time: {metrics.avg_generation_time_ms:.1f}ms
Active Nodes: {metrics.decoy_nodes_active}
  </pre>
</body></html>"""
