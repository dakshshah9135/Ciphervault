"""CipherVault | core/reporter.py — HTML audit log generator."""
import datetime
from pathlib import Path

def generate_report(operations: list, output_path: str) -> str:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = ""
    for op in operations:
        status_color = "#16a34a" if op.get("status") == "SUCCESS" else "#dc2626"
        rows += f"""
        <div style="border:1px solid #e5e7eb;border-left:4px solid {status_color};border-radius:10px;padding:1rem 1.25rem;margin-bottom:10px;background:#fff">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <div style="font-weight:700;color:#111;font-size:14px">{op.get('operation','Operation').upper()}</div>
            <span style="background:{status_color};color:#fff;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700">{op.get('status','—')}</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;font-size:12px">
            {"".join(f'<div style="background:#f8fafc;border-radius:6px;padding:6px 10px"><span style="color:#6b7280">{k}:</span> <strong style="color:#111;word-break:break-all">{v}</strong></div>' for k,v in op.items() if k not in ("operation","status"))}
          </div>
        </div>"""

    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/>
<title>CipherVault Audit Log</title>
<style>
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f3f4f6;margin:0;padding:2rem;color:#111827}}
  .wrap{{max-width:900px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}}
  .hd{{background:linear-gradient(135deg,#0f172a,#1a2b4a);color:#fff;padding:2rem 2.5rem}}
  .sec{{padding:1.5rem 2.5rem}}
  h2{{font-size:14px;font-weight:700;color:#1e293b;text-transform:uppercase;letter-spacing:.5px;padding-bottom:6px;border-bottom:2px solid #e5e7eb;margin-bottom:1rem}}
  footer{{text-align:center;padding:1rem;font-size:12px;color:#9ca3af;border-top:1px solid #f1f5f9}}
</style></head><body>
<div class="wrap">
  <div class="hd">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:.5rem">
      <div style="width:42px;height:42px;background:#3b82f6;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px">🔐</div>
      <div><div style="font-size:1.4rem;font-weight:800">CipherVault</div>
           <div style="font-size:11px;color:#94a3b8;letter-spacing:2px;text-transform:uppercase">Encryption Audit Log</div></div>
    </div>
    <div style="color:#94a3b8;font-size:13px">{ts} &nbsp;|&nbsp; {len(operations)} operation(s) recorded</div>
  </div>
  <div class="sec">
    <h2>Operations</h2>
    {rows if rows else '<p style="color:#6b7280">No operations recorded.</p>'}
  </div>
  <div class="sec" style="background:#fffbeb;border-top:1px solid #fef3c7">
    <div style="font-size:12px;color:#92400e">
      🔒 <strong>Security Note:</strong> CipherVault uses AES-256-CTR encryption with PBKDF2-HMAC-SHA256 key derivation
      (200,000 iterations) and HMAC-SHA256 integrity verification (encrypt-then-MAC pattern).
      Never share your password or store it alongside encrypted files.
    </div>
  </div>
  <footer>CipherVault v1.0 &nbsp;|&nbsp; Built by <strong>Daksh Shah</strong> &nbsp;|&nbsp; github.com/daksh-shah9135/ciphervault</footer>
</div></body></html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
