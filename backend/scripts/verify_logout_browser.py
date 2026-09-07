"""Verify visible logout, retry behavior and API session rejection on a test instance.

Requires Playwright/Chromium, CYBERSHIELD_BROWSER_PASSWORD, and optionally
CYBERSHIELD_BROWSER_URL (default: http://127.0.0.1:3200).
Uses the configured operator account and makes no scan requests.
"""
import json
import os
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

BASE = os.getenv("CYBERSHIELD_BROWSER_URL", "http://127.0.0.1:3200").rstrip("/")
password = os.environ["CYBERSHIELD_BROWSER_PASSWORD"]
OUTPUT = Path(os.getenv("CYBERSHIELD_BROWSER_OUTPUT", "/tmp/cybershield-logout-smoke"))
OUTPUT.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser=p.chromium.launch(executable_path=os.getenv('CYBERSHIELD_CHROMIUM', '/snap/bin/chromium'),headless=True,args=['--no-sandbox'])
    checks=[]
    for width,height in [(1440,1000),(390,844)]:
        context=browser.new_context(viewport={'width':width,'height':height})
        page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        base=BASE
        page.goto(base+'/login',wait_until='domcontentloaded')
        page.get_by_label('Work email',exact=True).fill('operator@cybershield.ai')
        page.get_by_label('Password',exact=True).fill(password)
        page.get_by_role('button',name='Sign in to workspace',exact=True).click()
        page.wait_for_url(base+'/',timeout=20000)
        button=page.locator('.workspace-header').get_by_role('button',name='Log out',exact=True)
        expect(button).to_be_visible(timeout=10000)
        assert 'Log out' in button.inner_text()
        box=button.bounding_box();assert box and box['x']>=0 and box['x']+box['width']<=width
        page.screenshot(path=str(OUTPUT/f'logout-{width}.png'))
        page.locator('.workspace-header').screenshot(path=str(OUTPUT/f'header-{width}.jpg'),type='jpeg',quality=75)
        pending=[]
        page.route('**/api/v1/auth/logout',lambda route:pending.append(route))
        button.click()
        expect(page.get_by_role('button',name='Logging out…',exact=True)).to_be_disabled()
        assert pending
        pending[0].fulfill(status=503,content_type='application/json',body='{"detail":"Temporary outage"}')
        expect(page.locator('.form-error[role=alert]')).to_contain_text('Logout could not be confirmed')
        expect(button).to_be_enabled()
        assert context.request.get(base+'/api/v1/auth/me').status==200
        page.unroute('**/api/v1/auth/logout')
        with page.expect_response(lambda r:r.url.endswith('/api/v1/auth/logout') and r.request.method=='POST') as response:button.click()
        assert response.value.status==200
        page.wait_for_url(base+'/login',timeout=15000)
        assert context.request.get(base+'/api/v1/auth/me').status==401
        page.goto(base+'/',wait_until='domcontentloaded');page.wait_for_url(base+'/login')
        assert not errors,errors
        checks.append({'width':width,'visible_labeled_logout':True,'backend_logout':200,'session_rejected_after_logout':401,'failed_logout_retry':True})
        context.close()
    browser.close();print(json.dumps({'checks':checks}))
