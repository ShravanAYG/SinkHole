import json


def render_js_verify_page(
    *,
    session_id: str,
    path: str,
    challenge: str,
    challenge_token: str,
    difficulty: int,
) -> str:
    """JS verification page with Proof-of-Work challenge.
    
    The browser must:
    1. Run environment checks
    2. Solve a SHA-256 Proof-of-Work puzzle (find nonce where hash has N leading zeros)
    3. Submit both the PoW solution and env check results to /bw/js-verify
    
    This makes scraping expensive — each page load costs 2-5 seconds of real CPU time.
    """
    sid_js = json.dumps(session_id)
    path_js = json.dumps(path)
    challenge_js = json.dumps(challenge)
    token_js = json.dumps(challenge_token)
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
    .progress {{ margin-top:0.5rem; color:var(--muted); font-size:0.8rem; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner" id="spinner"></div>
    <h1 id="title">Verifying browser...</h1>
    <p id="subtitle">Please wait while we confirm you're human</p>
    <div class="progress" id="progress"></div>
    <div class="status" id="status"></div>
  </div>
<script>
(async () => {{
  const SESSION_ID = {sid_js};
  const RETURN_PATH = {path_js};
  const CHALLENGE = {challenge_js};
  const CHALLENGE_TOKEN = {token_js};
  const DIFFICULTY = {difficulty};
  const statusEl = document.getElementById('status');
  const titleEl = document.getElementById('title');
  const subtitleEl = document.getElementById('subtitle');
  const spinnerEl = document.getElementById('spinner');
  const progressEl = document.getElementById('progress');
  
  // Pure JS SHA-256 fallback for HTTP (where crypto.subtle is undefined)
  const sha256 = function(ascii) {{
    function rightRotate(value, amount) {{ return (value>>>amount) | (value<<(32 - amount)); }}
    var mathPow = Math.pow, maxWord = mathPow(2, 32), lengthProperty = 'length', i, j, result = '';
    var words = [], asciiBitLength = ascii[lengthProperty]*8, hash = sha256.h = sha256.h || [], k = sha256.k = sha256.k || [], primeCounter = k[lengthProperty];
    var isComposite = {{}};
    for (var candidate = 2; primeCounter < 64; candidate++) {{
      if (!isComposite[candidate]) {{
        for (i = 0; i < 313; i += candidate) isComposite[i] = candidate;
        hash[primeCounter] = (mathPow(candidate, .5)*maxWord)|0;
        k[primeCounter++] = (mathPow(candidate, 1/3)*maxWord)|0;
      }}
    }}
    ascii += '\\x80';
    while (ascii[lengthProperty]%64 - 56) ascii += '\\x00';
    for (i = 0; i < ascii[lengthProperty]; i++) {{
      j = ascii.charCodeAt(i);
      if (j>>8) return;
      words[i>>2] |= j << ((3 - i)%4)*8;
    }}
    words[words[lengthProperty]] = ((asciiBitLength/maxWord)|0);
    words[words[lengthProperty]] = (asciiBitLength);
    for (j = 0; j < words[lengthProperty];) {{
      var w = words.slice(j, j += 16), oldHash = hash;
      hash = hash.slice(0, 8);
      for (i = 0; i < 64; i++) {{
        var w15 = w[i - 15], w2 = w[i - 2], a = hash[0], e = hash[4];
        var temp1 = hash[7] + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) + ((e&hash[5])^((~e)&hash[6])) + k[i] + (w[i] = (i < 16) ? w[i] : (w[i - 16] + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15>>>3)) + w[i - 7] + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2>>>10)))|0);
        var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) + ((a&hash[1])^(a&hash[2])^(hash[1]&hash[2]));
        hash = [(temp1 + temp2)|0].concat(hash);
        hash[4] = (hash[4] + temp1)|0;
      }}
      for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i])|0;
    }}
    for (i = 0; i < 8; i++) {{
      for (j = 3; j + 1; j--) {{
        var b = (hash[i]>>(j*8))&255;
        result += ((b < 16) ? 0 : '') + b.toString(16);
      }}
    }}
    return result;
  }};
  
  // SHA-256 Proof-of-Work solver
  async function solvePoW(challenge, difficulty) {{
    const target = '0'.repeat(difficulty);
    let nonce = 0;
    const startTime = performance.now();
    
    while (true) {{
      const hexNonce = nonce.toString(16);
      const hashHex = sha256(challenge + hexNonce);
      
      if (hashHex.startsWith(target)) {{
        const solveMs = Math.round(performance.now() - startTime);
        return {{ nonce: hexNonce, hash: hashHex, solveMs }};
      }}
      
      nonce++;
      
      // Update progress every 2000 iterations to yield to UI
      if (nonce % 2000 === 0) {{
        progressEl.textContent = 'Computing: ' + nonce.toLocaleString() + ' iterations...';
        await new Promise(r => setTimeout(r, 0));
      }}
    }}
  }}

  // Run browser environment checks
  function runChecks() {{
    const checks = {{ passed: 0, failed: 0, details: [] }};
    
    try {{ 
      if (typeof window !== 'undefined' && typeof document !== 'undefined') {{
        checks.passed++; checks.details.push('window_ok');
      }} else {{ checks.failed++; checks.details.push('window_fail'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('window_error'); }}
    
    try {{
      const nav = navigator;
      if (nav.userAgent && nav.language && nav.platform) {{
        checks.passed++; checks.details.push('navigator_ok');
      }} else {{ checks.failed++; checks.details.push('navigator_fail'); }}
      if (nav.webdriver === true) {{
        checks.failed++; checks.details.push('webdriver_detected');
      }} else {{ checks.passed++; checks.details.push('no_webdriver'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('navigator_error'); }}
    
    try {{
      if (screen.width > 0 && screen.height > 0 && screen.colorDepth >= 24) {{
        checks.passed++; checks.details.push('screen_ok');
      }} else {{ checks.failed++; checks.details.push('screen_fail'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('screen_error'); }}
    
    try {{
      if (document.createElement && document.querySelector && document.title) {{
        checks.passed++; checks.details.push('document_ok');
      }} else {{ checks.failed++; checks.details.push('document_fail'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('document_error'); }}
    
    try {{
      if (window.innerWidth > 0 && window.innerHeight > 0) {{
        checks.passed++; checks.details.push('window_dims_ok');
      }} else {{ checks.failed++; checks.details.push('window_dims_fail'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('window_error'); }}
    
    try {{
      const plugins = navigator.plugins;
      if (plugins && plugins.length > 0) {{
        checks.passed++; checks.details.push('plugins_ok:' + plugins.length);
      }} else {{ checks.failed++; checks.details.push('no_plugins'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('plugins_error'); }}
    
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

    // WebGL unmasked renderer
    try {{
      const c = document.createElement('canvas');
      const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (gl) {{
        const di = gl.getExtension('WEBGL_debug_renderer_info');
        if (di) {{
          const r = gl.getParameter(di.UNMASKED_RENDERER_WEBGL);
          if (r) {{
            const rL = r.toLowerCase();
            if (rL.includes('swiftshader') || rL.includes('llvmpipe') || rL.includes('virtualbox')) {{
              checks.failed++; checks.details.push('software_renderer:' + r.substring(0,40));
            }} else {{
              checks.passed++; checks.details.push('hardware_gpu:' + r.substring(0,40));
            }}
          }} else {{ checks.failed++; checks.details.push('no_renderer'); }}
        }} else {{ checks.failed++; checks.details.push('no_webgl_debug'); }}
      }} else {{ checks.failed++; checks.details.push('no_webgl'); }}
    }} catch(e) {{ checks.failed++; checks.details.push('webgl_error'); }}

    // Automation variable scan
    try {{
      let found = false;
      const botKeys = ['cdc_','$cdc_','__webdriver','_phantom','__nightmare','__playwright','__selenium'];
      for (const key of Object.getOwnPropertyNames(window)) {{
        for (const bk of botKeys) {{
          if (key.startsWith(bk) || key.includes(bk)) {{ found = true; break; }}
        }}
        if (found) break;
      }}
      if (found) {{
        checks.failed++; checks.details.push('automation_vars');
      }} else {{
        checks.passed++; checks.details.push('no_automation_vars');
      }}
    }} catch(e) {{ checks.failed++; checks.details.push('automation_check_error'); }}

    // Stealth plugin proxy detection
    try {{
      let proxied = false;
      try {{
        const d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
        if (d && d.get) {{
          const s = Function.prototype.toString.call(d.get);
          if (!s.includes('[native code]')) proxied = true;
        }}
      }} catch(e) {{}}
      if (proxied) {{
        checks.failed++; checks.details.push('stealth_proxy');
      }} else {{
        checks.passed++; checks.details.push('native_getters');
      }}
    }} catch(e) {{ checks.failed++; checks.details.push('stealth_check_error'); }}

    return checks;
  }}

  // Submit both PoW solution and env checks
  async function submit(powResult, checks) {{
    try {{
      const res = await fetch('/bw/js-verify', {{
        method: 'POST',
        headers: {{ 'content-type': 'application/json' }},
        body: JSON.stringify({{
          session_id: SESSION_ID,
          return_path: RETURN_PATH,
          challenge_token: CHALLENGE_TOKEN,
          challenge: CHALLENGE,
          nonce: powResult.nonce,
          hash: powResult.hash,
          solve_ms: powResult.solveMs,
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
        progressEl.textContent = '';
        setTimeout(() => location.replace(result.next_path || RETURN_PATH), 500);
      }} else {{
        titleEl.textContent = 'Verification Failed';
        subtitleEl.textContent = 'Access denied';
        statusEl.className = 'status err';
        statusEl.textContent = result.error || 'Redirecting...';
        spinnerEl.style.display = 'none';
        progressEl.textContent = '';
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
      progressEl.textContent = '';
    }}
  }}
  
  // 1. Run environment checks
  const checks = runChecks();
  
  // 2. Solve proof-of-work
  subtitleEl.textContent = 'Solving challenge...';
  const powResult = await solvePoW(CHALLENGE, DIFFICULTY);
  progressEl.textContent = 'Solved in ' + powResult.solveMs + 'ms';
  
  // 3. Submit everything
  subtitleEl.textContent = 'Submitting verification...';
  await submit(powResult, checks);
}})();
</script>
</body>
</html>"""
