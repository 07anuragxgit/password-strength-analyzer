# password_analyzer_web.py
# Simple Flask web UI for your Password Strength Analyzer (SHA-256 demo)

from flask import Flask, request, render_template_string
import re
import hashlib

app = Flask(__name__)

def check_strength(password: str):
    checks = {
        "length": len(password) >= 8,
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"[0-9]", password)),
        "special": bool(re.search(r"[@$!%*?&]", password)),
    }
    score = sum(checks.values())
    suggestions = []
    if not checks["length"]:
        suggestions.append("Use at least 8 characters (longer is better).")
    if not checks["lower"]:
        suggestions.append("Add lowercase letters (a, b, c...).")
    if not checks["upper"]:
        suggestions.append("Add uppercase letters (A, B, C...).")
    if not checks["digit"]:
        suggestions.append("Include numeric digits (0-9).")
    if not checks["special"]:
        suggestions.append("Add special characters (e.g. @, #, $ , !).")
    return score, checks, suggestions

def strength_label(score: int):
    if score == 5:
        return "Very Strong", "success"
    if score >= 3:
        return "Moderate", "warning"
    return "Weak", "danger"

def sha256_hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Password Analyzer — Demo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body { background: #f8fafc; }
      .card { max-width: 780px; margin: 40px auto; }
      pre.hashbox { background:#0f172a; color:#e6eef8; padding:12px; border-radius:6px; overflow-x:auto }
      .checklist li { margin-bottom:6px }
    </style>
  </head>
  <body>
    <div class="card shadow-sm">
      <div class="card-body">
        <h3 class="card-title">Password Strength Analyzer</h3>
        <p class="text-muted small">Enter a password to evaluate strength and see its SHA-256 hash (demo).</p>

        <form method="post" action="/analyze">
          <div class="mb-3">
            <label for="password" class="form-label">Password</label>
            <div class="input-group">
              <input type="password" class="form-control" id="password" name="password" placeholder="Type password" required>
              <button class="btn btn-outline-secondary" type="button" id="toggle">Show</button>
            </div>
            <div class="form-text">Your password is not stored on a remote server in this demo.</div>
          </div>

          <div class="mb-3">
            <button class="btn btn-primary" type="submit">Analyze</button>
            <a href="/" class="btn btn-link">Reset</a>
          </div>
        </form>

        {% if analyzed %}
        <hr>
        <h5>Result</h5>
        <div class="mb-2">
          <span class="badge bg-{{ badge_class }}">{{ label }}</span>
          <small class="text-muted ms-2">(Score: {{ score }}/5)</small>
        </div>

        <div class="row">
          <div class="col-md-6">
            <h6>Checklist</h6>
            <ul class="list-unstyled checklist">
              <li>{{ '✅' if checks.length else '❌' }} Length (≥ 8)</li>
              <li>{{ '✅' if checks.lower else '❌' }} Lowercase</li>
              <li>{{ '✅' if checks.upper else '❌' }} Uppercase</li>
              <li>{{ '✅' if checks.digit else '❌' }} Digit</li>
              <li>{{ '✅' if checks.special else '❌' }} Special character</li>
            </ul>

            {% if suggestions %}
            <h6>Suggestions</h6>
            <ul>
              {% for s in suggestions %}
                <li>{{ s }}</li>
              {% endfor %}
            </ul>
            {% endif %}

          </div>
          <div class="col-md-6">
            <h6>SHA-256 Hash (demo)</h6>
            <pre class="hashbox">{{ hash_val }}</pre>
            <button class="btn btn-sm btn-outline-secondary" onclick="copyHash()">Copy Hash</button>
          </div>
        </div>
        {% endif %}

        <hr>
        <p class="small text-muted mb-0">Tip: For portfolio screenshots — take a shot of the result panel (the badge, checklist and hash). Don't show real user data.</p>
      </div>
    </div>

    <script>
      const pwd = document.getElementById('password');
      const toggle = document.getElementById('toggle');
      toggle.addEventListener('click', ()=>{
        if(pwd.type === 'password'){ pwd.type='text'; toggle.textContent='Hide'; }
        else { pwd.type='password'; toggle.textContent='Show'; }
      });
      function copyHash(){
        const hashText = document.querySelector('.hashbox').innerText;
        navigator.clipboard.writeText(hashText).then(()=>{
          alert('Hash copied to clipboard');
        });
      }
    </script>
  </body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(TEMPLATE, analyzed=False)

@app.route('/analyze', methods=['POST'])
def analyze():
    password = request.form.get('password', '')
    score, checks, suggestions = check_strength(password)
    label, badge_class = strength_label(score)
    hash_val = sha256_hash(password)

    class C: pass
    c = C()
    c.length = checks['length']
    c.lower = checks['lower']
    c.upper = checks['upper']
    c.digit = checks['digit']
    c.special = checks['special']

    return render_template_string(TEMPLATE,
                                  analyzed=True,
                                  score=score,
                                  checks=c,
                                  suggestions=suggestions,
                                  label=label,
                                  badge_class=badge_class,
                                  hash_val=hash_val)

if __name__ == '__main__':
    app.run(debug=True)
