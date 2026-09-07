"""Browser regression for saved/streamed partial outcomes and stream errors.

Uses mocked API responses against a local frontend. Never starts a real scan.
"""
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, expect

BASE = os.getenv('CYBERSHIELD_BROWSER_URL', 'http://127.0.0.1:3120')
OUTPUT = Path(os.getenv('CYBERSHIELD_BROWSER_OUTPUT', '/tmp/cybershield-partial-browser'))
OUTPUT.mkdir(parents=True, exist_ok=True)
assert urlsplit(BASE).hostname in ('localhost', '127.0.0.1')
state = {'domain':'example.invalid','execution_mode':'rules_only','all_findings':[],
         'scan_progress':{'recon':'partial','pentest':'partial','report':'completed'},
         'report_status':'success','pdf_path':'test.pdf','executive_summary':'Available evidence.', 'security_score':None}
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path='/snap/bin/chromium',headless=True,args=['--no-sandbox'])
    for case in ('saved-partial','streamed-partial','stream-error'):
        context=browser.new_context();page=context.new_page()
        job={'id':'test-scan','status':'partial' if case=='saved-partial' else 'running',
             'config':{'domain':'example.invalid','execution_mode':'rules_only','scope_type':'full_pentest'},
             'result':state if case=='saved-partial' else None,'error':None}
        def api(route):
            path=urlsplit(route.request.url).path
            if path=='/api/v1/auth/me': data={'email':'test@example.invalid','role':'operator'}
            elif path=='/api/scans': data=[job]
            elif path=='/api/scans/test-scan': data=job
            elif path.endswith('/events'):
                body='data: invalid-event\n\n' if case=='stream-error' else 'data: '+json.dumps({'type':'complete','status':'partial','state':state})+'\n\n'
                route.fulfill(status=200,content_type='text/event-stream',body=body);return
            else: route.fulfill(status=404,body='{}');return
            route.fulfill(status=200,content_type='application/json',body=json.dumps(data))
        context.route('**/api/**',api)
        page.goto(BASE+'/',wait_until='domcontentloaded');page.locator('.history-row').click()
        if case=='stream-error':
            expect(page.get_by_text('The scan stream returned an invalid event. Reconnect to resume.')).to_be_visible()
            expect(page.get_by_role('button',name='Reconnect',exact=True).first).to_be_visible()
        else:
            expect(page.get_by_text('Assessment finished with incomplete coverage.',exact=True)).to_be_visible()
            expect(page.locator('.coverage-notice')).to_contain_text('Reconnaissance, Active assessment')
            expect(page.get_by_role('button',name='Reconnect',exact=True)).to_have_count(0)
            expect(page.locator('.form-error')).to_have_count(0)
            if case == 'saved-partial':
                for width in (1440, 390):
                    page.set_viewport_size({'width':width,'height':1000})
                    notice=page.locator('.coverage-notice');box=notice.bounding_box()
                    assert box and box['x'] >= 0 and box['x']+box['width'] <= width
                    notice.screenshot(path=str(OUTPUT / f'coverage-{width}.png'))
            page.get_by_role('button',name='Reports',exact=True).click()
            expect(page.get_by_role('button',name='Download PDF',exact=True)).to_be_enabled()
        print(case+': passed',flush=True);context.close()
    browser.close()
