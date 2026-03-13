"""
Renderer for embeddings-based enhanced decoy pages.

These pages include:
- Semantically plausible but factually false content
- Hidden markers visible to humans but invisible to bots
- Professional appearance that passes automated quality checks
"""

from __future__ import annotations

import html
from typing import Any


def render_embeddings_decoy_page(
    node: Any,  # EnhancedDecoyNode
    session_id: str,
    show_human_markers: bool = True,
) -> str:
    """
    Render an enhanced decoy page with embeddings-based fake content.
    
    Args:
        node: EnhancedDecoyNode with fake content
        session_id: Session identifier
        show_human_markers: Whether to show human-detectable markers
    
    Returns:
        HTML string for the decoy page
    """
    links_html = "".join(
        f'<li><a href="/bw/decoy/{child}?sid={html.escape(session_id)}">Related archive {child:03d}</a></li>'
        for child in node.links
    )
    
    # Render body content with styling
    body_html_parts = []
    for line in node.body:
        # Check if it's a table (contains | characters)
        if "|" in line and "\n" in line:
            # Format as preformatted table
            body_html_parts.append(f'<pre class="data-table">{html.escape(line)}</pre>')
        else:
            body_html_parts.append(f"<p>{html.escape(line)}</p>")
    
    body_html = "".join(body_html_parts)
    
    # Hidden markers section (only visible to humans who know to look)
    markers_section = ""
    if show_human_markers and hasattr(node, 'hidden_markers') and node.hidden_markers:
        markers_list = "".join(
            f'<li class="marker-item">{html.escape(marker)}</li>' 
            for marker in node.hidden_markers
        )
        markers_section = f"""
        <div class="human-verification-panel">
            <h3>🔍 Human Verification Panel</h3>
            <p class="panel-desc">The following markers indicate this content is synthetic:</p>
            <ul class="marker-list">
                {markers_list}
            </ul>
            <p class="panel-footer">These markers are obvious to humans but invisible to automated systems.</p>
        </div>
        """
    
    # Metadata display (subtle indicator this is decoy content)
    metadata_section = ""
    if hasattr(node, 'metadata') and node.metadata:
        meta_type = node.metadata.get('type', 'embeddings')
        coherence = node.metadata.get('coherence_score', 'N/A')
        falsehood = node.metadata.get('falsehood_density', 'N/A')
        metadata_section = f"""
        <div class="metadata-footer">
            <small>Content Type: {html.escape(str(meta_type))} | 
            Coherence: {html.escape(str(coherence))} | 
            Falsehood Density: {html.escape(str(falsehood))}</small>
        </div>
        """
    
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>{html.escape(node.title)}</title>
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
      line-height: 1.6; 
    }}
    .container {{ 
      max-width: 900px; 
      margin: 2rem auto; 
      padding: 0 1.5rem; 
    }}
    header {{ 
      background: var(--surface); 
      border-bottom: 1px solid var(--border); 
      padding: 1.5rem 2rem; 
      margin-bottom: 2rem;
    }}
    header h1 {{ 
      font-size: 1.5rem; 
      font-weight: 600; 
      color: var(--text);
    }}
    header .subtitle {{ 
      color: var(--muted); 
      font-size: 0.9rem; 
      margin-top: 0.25rem;
    }}
    .content-card {{ 
      background: var(--surface); 
      border: 1px solid var(--border); 
      border-radius: 12px; 
      padding: 2rem; 
      margin-bottom: 1.5rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }}
    .content-card p {{ 
      margin-bottom: 1rem; 
      text-align: justify;
    }}
    .content-card p:last-child {{ 
      margin-bottom: 0; 
    }}
    .data-table {{ 
      background: #f1f3f5; 
      border: 1px solid var(--border); 
      border-radius: 8px; 
      padding: 1rem; 
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace;
      font-size: 0.85rem;
      overflow-x: auto;
      margin: 1rem 0;
    }}
    .bait {{ 
      letter-spacing: 0.05em; 
      text-transform: uppercase; 
      color: var(--muted);
      font-size: 0.75rem;
      margin-top: 1.5rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
    }}
    .links-section {{ 
      background: var(--surface); 
      border: 1px solid var(--border); 
      border-radius: 12px; 
      padding: 1.5rem;
    }}
    .links-section h2 {{ 
      font-size: 1.1rem; 
      margin-bottom: 1rem; 
      color: var(--text);
    }}
    .links-section ul {{ 
      list-style: none; 
      padding: 0;
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 0.75rem;
    }}
    .links-section li a {{ 
      color: var(--accent); 
      text-decoration: none; 
      padding: 0.5rem 0.75rem;
      background: #f1f3f5;
      border-radius: 6px;
      display: block;
      font-size: 0.9rem;
      transition: background 0.2s;
    }}
    .links-section li a:hover {{ 
      background: #e7f3ff;
    }}
    .human-verification-panel {{ 
      background: linear-gradient(135deg, #fff3cd 0%, #ffe69c 100%);
      border: 2px solid var(--warning);
      border-radius: 12px;
      padding: 1.5rem;
      margin-top: 2rem;
      box-shadow: 0 4px 12px rgba(255, 193, 7, 0.15);
    }}
    .human-verification-panel h3 {{ 
      color: #856404;
      font-size: 1.1rem;
      margin-bottom: 0.75rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .panel-desc {{ 
      color: #856404; 
      font-size: 0.95rem; 
      margin-bottom: 1rem;
    }}
    .marker-list {{ 
      list-style: none; 
      padding: 0;
    }}
    .marker-item {{ 
      padding: 0.5rem 0;
      padding-left: 1.5rem;
      position: relative;
      color: #856404;
      font-weight: 500;
    }}
    .marker-item::before {{ 
      content: "⚠️";
      position: absolute;
      left: 0;
    }}
    .panel-footer {{ 
      margin-top: 1rem;
      padding-top: 1rem;
      border-top: 1px solid rgba(133, 100, 4, 0.2);
      color: #856404;
      font-size: 0.85rem;
      font-style: italic;
    }}
    .recovery-link {{ 
      text-align: center; 
      margin-top: 2rem; 
      padding-top: 1.5rem;
      border-top: 1px solid var(--border);
    }}
    .recovery-link a {{ 
      color: var(--muted); 
      text-decoration: none;
      font-size: 0.9rem;
    }}
    .recovery-link a:hover {{ 
      color: var(--accent);
    }}
    .metadata-footer {{ 
      text-align: center; 
      margin-top: 1.5rem; 
      color: var(--muted);
      font-size: 0.75rem;
    }}
    .poison-notice {{ 
      background: linear-gradient(90deg, rgba(220, 53, 69, 0.1), rgba(255, 193, 7, 0.1));
      border: 1px dashed var(--danger);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 1.5rem;
      text-align: center;
      font-size: 0.85rem;
      color: var(--danger);
    }}
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
    <div class="poison-notice">
      🎭 <strong>Data Poisoning Active</strong> — This page contains synthetic content designed to corrupt scraped datasets.
    </div>
    
    <div class="content-card">
      {body_html}
      <p class="bait">SCAN-PRIORITY ACTION-QUEUE VERIFY-ENTRY AUTH-KEY TOKEN-VERIFY</p>
    </div>
    
    <div class="links-section">
      <h2>Continue browsing</h2>
      <ul>{links_html}</ul>
    </div>
    
    {markers_section}
    
    <div class="recovery-link">
      <p>Having trouble? <a href="/bw/recovery">Request human recovery</a></p>
    </div>
    
    {metadata_section}
  </main>
  
  <script>
    // Hidden signal for human verification
    // This code is inert but proves the page is client-side rendered
    (function() {{
      console.log("%c🔍 Human Verification", "font-size: 20px; color: #ffc107;");
      console.log("%cThis content is SYNTHETIC — check the Human Verification Panel below.", "font-size: 14px; color: #856404;");
    }})();
  </script>
</body>
</html>"""
