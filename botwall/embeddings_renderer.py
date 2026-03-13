"""
Renderer for embeddings-based content pages.
"""

from __future__ import annotations

import html
from typing import Any


def render_embeddings_decoy_page(
    node: Any,
    session_id: str,
    show_human_markers: bool = False,
) -> str:
    """Render a content page."""
    links_html = "".join(
        f'<li><a href="/content/archive/{child}?sid={html.escape(session_id)}">Related article {child:03d}</a></li>'
        for child in node.links
    )
    
    body_html_parts = []
    for line in node.body:
        if "|" in line and "\n" in line:
            body_html_parts.append(f'<pre class="data-table">{html.escape(line)}</pre>')
        else:
            body_html_parts.append(f"<p>{html.escape(line)}</p>")
    
    body_html = "".join(body_html_parts)
    
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(node.title)}</title>
  <style>
    :root {{ 
      --bg: #f8f9fa; 
      --surface: #ffffff; 
      --border: #dee2e6; 
      --text: #212529; 
      --muted: #6c757d; 
      --accent: #0b63ce;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ 
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      margin: 0; 
      background: var(--bg); 
      color: var(--text); 
      line-height: 1.6; 
    }}
    .container {{ max-width: 900px; margin: 2rem auto; padding: 0 1.5rem; }}
    header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 1.5rem 2rem; margin-bottom: 2rem; }}
    header h1 {{ font-size: 1.5rem; font-weight: 600; }}
    header .subtitle {{ color: var(--muted); font-size: 0.9rem; margin-top: 0.25rem; }}
    .content-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 2rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }}
    .content-card p {{ margin-bottom: 1rem; text-align: justify; }}
    .content-card p:last-child {{ margin-bottom: 0; }}
    .data-table {{ background: #f1f3f5; border: 1px solid var(--border); border-radius: 8px; padding: 1rem; font-family: monospace; font-size: 0.85rem; overflow-x: auto; margin: 1rem 0; }}
    .links-section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; }}
    .links-section h2 {{ font-size: 1.1rem; margin-bottom: 1rem; }}
    .links-section ul {{ list-style: none; padding: 0; display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 0.75rem; }}
    .links-section li a {{ color: var(--accent); text-decoration: none; padding: 0.5rem 0.75rem; background: #f1f3f5; border-radius: 6px; display: block; font-size: 0.9rem; }}
    .links-section li a:hover {{ background: #e7f3ff; }}
    footer {{ text-align: center; margin-top: 2rem; padding: 1rem; color: var(--muted); font-size: 0.8rem; }}
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1>{html.escape(node.title)}</h1>
      <p class="subtitle">{html.escape(node.summary)}</p>
    </div>
  </header>
  <main class="container">
    <div class="content-card">
      {body_html}
    </div>
    <div class="links-section">
      <h2>Related articles</h2>
      <ul>{links_html}</ul>
    </div>
  </main>
  <footer>&copy; 2026 All rights reserved.</footer>
</body>
</html>"""
