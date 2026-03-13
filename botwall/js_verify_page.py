def render_js_verify_page(*, session_id: str, path: str) -> str:
    """Lightweight JS verification - runs browser env checks."""
    sid_js = json.dumps(session_id)
    path_js = json.dumps(path)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>Verifying...</title>
  <style>
    :root {{ --bg:#0f1117; --surface:#171c28; --text:#dbe6f4; --muted:#7f8ba5; --accent:#4dd0e1; --ok:#22c55e; --err:#ef4444; }}
    * {{ box-sizing: border-box; margin:0; padding:0; }}
    body {{ margin:0; min-height:100dvh; background:var(--bg); color:var(--text); font-family:"Inter","Segoe UI",system-ui,sans-serif; display:grid; place-items:center; }}
    .card {{ width:min(420px,90%); padding:2rem; background:var(--surface); border-radius:16px; text-align:center; }}
    .spinner {{ width:48px; height:48px; border:3px solid var(--muted); border-top-color:var(--accent); border-radius:50%; margin:0 auto 1rem; animation:spin 1s linear infinite; }}
    @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
    h1 {{ font-size:1.25rem; margin-bottom:0.5rem; }}
    p {{ color:var(--muted); font-size:0.9rem; }}
    .status {{ margin-top:1rem; padding:0.75rem; border-radius:8px; font-size:0.85rem; display:none; }}
    .status.ok {{ display:block; background:rgba(34,197,94,0.15); color:var(--ok); }}
    .status.err {{ display:block; background:rgba(239,68,68,0.15); color:var(--err); }}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner" id="spinner"></div>
    <h1 id="title">Verifying browser...</h1>
    <p id="subtitle">Please wait while we confirm you're human</p>
    <div class="status" id="status"></div>
  </div>
<script>
(async () => {{
  const SESSION_ID = {sid_js};
  const RETURN_PATH = {path_js};
  const statusEl = document.getElementById('status');
  const titleEl = document.getElementById('title');
  const subtitleEl = document.getElementById('subtitle');
  const spinnerEl = document.getElementById('spinner');
  
  // Run browser verification checks
  async function runChecks() {{
    const checks = {{ passed: 0, failed: 0, details: [] }};
    
    // Check 1: window and document exist
    try {{ 
      if (typeof window !== 'undefined' && typeof document !== 'undefined') {{
        checks.passed++; checks.details.push('window_ok');
      }} else {{ checks.failed++; checks.details.push('window_fail'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('window_error'); }}
    
    // Check 2: navigator properties
    try {{
      const nav = navigator;
      if (nav.userAgent && nav.language && nav.platform) {{
        checks.passed++; checks.details.push('navigator_ok');
      }} else {{ checks.failed++; checks.details.push('navigator_fail'); }}
      // Check webdriver (automation marker)
      if (nav.webdriver === true) {{
        checks.failed++; checks.details.push('webdriver_detected');
      }} else {{ checks.passed++; checks.details.push('no_webdriver'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('navigator_error'); }}
    
    // Check 3: screen properties
    try {{
      if (screen.width > 0 && screen.height > 0 && screen.colorDepth >= 24) {{
        checks.passed++; checks.details.push('screen_ok');
      }} else {{ checks.failed++; checks.details.push('screen_fail'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('screen_error'); }}
    
    // Check 4: document properties
    try {{
      if (document.createElement && document.querySelector && document.title) {{
        checks.passed++; checks.details.push('document_ok');
      }} else {{ checks.failed++; checks.details.push('document_fail'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('document_error'); }}
    
    // Check 5: window properties
    try {{
      if (window.innerWidth > 0 && window.innerHeight > 0 && typeof window.location === 'object') {{
        checks.passed++; checks.details.push('window_dims_ok');
      }} else {{ checks.failed++; checks.details.push('window_dims_fail'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('window_error'); }}
    
    // Check 6: plugins (real browsers have plugins)
    try {{
      const plugins = navigator.plugins;
      if (plugins && plugins.length > 0) {{
        checks.passed++; checks.details.push('plugins_ok:' + plugins.length);
      }} else {{ checks.failed++; checks.details.push('no_plugins'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('plugins_error'); }}
    
    // Check 7: canvas fingerprint (basic test)
    try {{
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#4dd0e1';
      ctx.fillRect(0,0,50,50);
      const data = canvas.toDataURL();
      if (data && data.length > 100) {{
        checks.passed++; checks.details.push('canvas_ok');
      }} else {{ checks.failed++; checks.details.push('canvas_fail'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('canvas_error'); }}
    
    return checks;
  }}
  
  // Submit verification
  async function submitVerification(checks) {{
    try {{
      const res = await fetch('/bw/js-verify', {{
        method: 'POST',
        headers: {{ 'content-type': 'application/json' }},
        body: JSON.stringify({{
          session_id: SESSION_ID,
          checks: checks,
          timestamp: Date.now()
        }}),
        credentials: 'same-origin'
      }});
      
      const result = await res.json();
      
      if (result.ok && result.decision === 'allow') {{
        titleEl.textContent = 'Verified!';
        subtitleEl.textContent = 'Redirecting to content...';
        statusEl.className = 'status ok';
        statusEl.textContent = 'Browser verification passed';
        setTimeout(() => location.replace(result.next_path || RETURN_PATH), 500);
      }} else {{
        titleEl.textContent = 'Verification Failed';
        subtitleEl.textContent = 'Browser automation detected';
        statusEl.className = 'status err';
        statusEl.textContent = result.error || 'Redirecting to safe page...';
        spinnerEl.style.display = 'none';
        if (result.next_path) {{
          setTimeout(() => location.replace(result.next_path), 1500);
        }}
      }}
    }} catch(err) {{
      titleEl.textContent = 'Error';
      subtitleEl.textContent = 'Please try again';
      statusEl.className = 'status err';
      statusEl.textContent = err.message;
      spinnerEl.style.display = 'none';
    }}
  }}
  
  // Run checks and submit
  const checks = await runChecks();
  await submitVerification(checks);
}})();
</script>
</body>
</html>"""
