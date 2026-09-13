/* Separate reviewer authority; source text is never rendered as HTML. */
(() => {
  'use strict';
  const el = id => document.getElementById(id);
  let credential = '', draft = null, generation = 0, busy = false;
  const status = text => { el('review-status').textContent = text; };
  function invalidate() {
    draft = null;
    el('review-approve').disabled = true;
    el('review-details').hidden = true;
    el('review-summary').textContent = '';
  }
  function render() {
    el('review-connect').disabled = busy;
    el('review-disconnect').disabled = !credential && !busy;
    el('review-preview').disabled = !credential || busy;
    el('review-approve').disabled = !credential || !draft || busy;
    el('review-proposal').disabled = busy;
  }
  function disconnect() {
    generation++; credential = ''; busy = false; invalidate();
    el('review-identity').textContent = '';
    el('review-token').value = ''; el('review-proposal').value = '';
    el('review-result').textContent = '';
    status('Disconnected. No new approval will be submitted. A submitted approval may already have been saved.');
    render();
  }
  async function call(path, token, body) {
    const response = await fetch('/v1/reviews/' + path, {
      method: body === undefined ? 'GET' : 'POST', cache: 'no-store',
      headers: {Authorization: 'Bearer ' + token, 'Content-Type': 'application/json'},
      ...(body === undefined ? {} : {body})
    });
    if (!response.ok) throw new Error('Request declined or unavailable (' + response.status + '). Reconnect and review before retrying.');
    return response.json();
  }
  el('review-connect').addEventListener('click', async () => {
    const token = el('review-token').value.trim(); disconnect();
    if (!token) { status('Enter your separate reviewer credential.'); return; }
    const version = generation; busy = true; render();
    try {
      const profile = await call('me', token);
      if (version !== generation) return;
      credential = token;
      el('review-identity').textContent = 'Reviewer: ' + profile.subject + ' · Tenant: ' + profile.tenant;
      status('Reviewer: ' + profile.subject + ' · Tenant: ' + profile.tenant + '. Credential authentication; passkey sign-in is not configured.');
    } catch (error) { if (version === generation) status(error.message); }
    finally { if (version === generation) { busy = false; render(); } }
  });
  el('review-disconnect').addEventListener('click', disconnect);
  el('review-token').addEventListener('input', () => {
    if (credential || busy) { const value = el('review-token').value; disconnect(); el('review-token').value = value; }
  });
  el('review-proposal').addEventListener('input', () => { invalidate(); el('review-result').textContent = ''; render(); });
  el('review-discard').addEventListener('click', () => {
    invalidate(); el('review-proposal').value = ''; el('review-result').textContent = 'Local draft discarded. No revocation was performed.'; render();
  });
  el('review-preview').addEventListener('click', async () => {
    if (!credential || busy) return;
    invalidate(); el('review-result').textContent = '';
    let proposal;
    try { proposal = JSON.stringify(JSON.parse(el('review-proposal').value)); }
    catch { status('Enter a valid JSON action proposal.'); return; }
    const version = generation; busy = true; render();
    try {
      const result = await call('preview', credential, proposal);
      if (version !== generation) return;
      draft = proposal;
      el('review-summary').textContent = JSON.stringify(result, null, 2);
      el('review-details').hidden = false;
      status('Review every field. The proposal is not approved and has not executed.');
    } catch (error) { if (version === generation) status(error.message); }
    finally { if (version === generation) { busy = false; render(); } }
  });
  el('review-approve').addEventListener('click', async () => {
    if (!credential || !draft || busy) return;
    const proposal = draft, version = generation; draft = null; busy = true; render();
    try {
      const result = await call('approve', credential, proposal);
      if (version !== generation) return;
      invalidate(); el('review-proposal').value = '';
      el('review-result').textContent = 'Approval saved: ' + result.approval_id + '. Expires: ' + new Date(result.expires_at * 1000).toISOString() + '. No action was executed.';
      status('Single-use approval recorded for your authenticated identity.');
    } catch (error) {
      if (version === generation) { invalidate(); status('Approval outcome may be unknown. Do not automatically retry. ' + error.message); }
    } finally { if (version === generation) { busy = false; render(); } }
  });
  window.addEventListener('pagehide', disconnect);
  render();
})();
