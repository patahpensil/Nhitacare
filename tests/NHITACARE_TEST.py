"""Reproducible staging checks. Requires Python, Node.js, bs4 and Playwright Chromium."""
import sys, re, json, hashlib, base64, subprocess, tempfile, zipfile, html
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urlsplit, unquote
from playwright.sync_api import sync_playwright
results=[]
def check(name, condition):
    results.append({'test':name,'pass':bool(condition)})
def run(root):
    pages={p.name:BeautifulSoup(p.read_text(),'html.parser') for p in root.glob('*.html')}
    csp=re.search(r'Content-Security-Policy: (.*)',(root/'_headers').read_text())[1]
    for name,soup in pages.items():
        for i,s in enumerate(soup.find_all('script')):
            code=s.string or ''
            with tempfile.NamedTemporaryFile(suffix='.js') as f:
                f.write(code.encode());f.flush();check(f'{name} JS {i}',subprocess.run(['node','--check',f.name],capture_output=True).returncode==0)
            check(f'{name} CSP {i}',base64.b64encode(hashlib.sha256(code.encode()).digest()).decode() in csp)
        for a in soup.find_all('a',href=True):
            u=urlsplit(a['href']); target=unquote(u.path) or name
            if not u.scheme and not u.netloc and a['href']!='#':
                check(f'{name} link {a["href"]}',target in pages and (not u.fragment or pages[target].find(id=u.fragment) is not None))
    check('Map target', 'Kabupaten%20Sidenreng%20Rappang' in pages['index.html'].iframe['src'])
    check('Map CSP', 'frame-src https://maps.google.com' in csp)
    for line in (root/'SHA256SUMS.txt').read_text().splitlines():
        digest,name=line.split(maxsplit=1);check('checksum '+name,hashlib.sha256((root/name).read_bytes()).hexdigest()==digest)
    with sync_playwright() as pw:
        b=pw.chromium.launch(executable_path='/usr/bin/chromium' if Path('/usr/bin/chromium').exists() else None,args=['--no-sandbox'])
        for w in [320,390,768,1440]:
            p=b.new_page(viewport={'width':w,'height':900});p.route('**/*',lambda r:r.abort());errors=[];p.on('pageerror',lambda e:errors.append(str(e)))
            for name in pages:
                errors.clear();p.set_content((root/name).read_text().replace('<head>','<head><meta http-equiv="Content-Security-Policy" content="'+html.escape(csp,quote=True)+'">',1),wait_until='domcontentloaded',timeout=15000)
                check(f'{w}/{name} overflow',p.evaluate('document.documentElement.scrollWidth<=innerWidth'));check(f'{w}/{name} JS errors',not errors)
                if name=='layanan.html':
                    check(f'{w} catalog',p.locator('.svc').count()==19);p.locator('#q').fill('GERD');check(f'{w} search',p.locator('.svc:not([hidden])').count()==1);p.locator('#q').fill('')
                    for k,n in [('kp',3),('vk',3),('inf',2),('kel',5),('gh',4),('reh',1),('kor',1),('all',19)]:
                        p.locator(f'.tab[data-k={k}]').evaluate('(a)=>a.click()');check(f'{w} filter {k}',p.locator('.svc:not([hidden])').count()==n)
            p.close()
        b.close()
if __name__=='__main__':
    try:
        with tempfile.TemporaryDirectory() as d:
            source=Path(sys.argv[1]);root=Path(d) if source.is_file() else source
            if source.is_file():
                with zipfile.ZipFile(source) as z:z.extractall(root)
            run(root)
    finally:
        print(json.dumps({'total':len(results),'passed':sum(r['pass'] for r in results),'results':results},indent=2))
    sys.exit(0 if results and all(r['pass'] for r in results) else 1)
