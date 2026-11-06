let inventory = null;
const el = id => document.getElementById(id);
const date = value => new Date(value).toLocaleString();
function renderUsers() {
  if (!inventory) return;
  const query = el('search').value.toLocaleLowerCase();
  const users = inventory.users.filter(user => user.name.toLocaleLowerCase().includes(query));
  const rows = users.map(user => {
    const row = document.createElement('tr');
    [user.name, user.passwordRequired ? 'Certificate + password' : 'Certificate only', user.credentialCount, user.activeSessions, user.certificateRevoked === true ? 'Revoked' : user.certificateIssued ? (user.certificateRevoked === false ? 'Issued' : 'PFX present (status unknown)') : 'No PFX file'].forEach((value, index) => {
      const cell = document.createElement('td');
      const node = index === 1 ? document.createElement('span') : cell;
      if (index === 1) { node.className = 'pill' + (user.passwordRequired ? '' : ' passwordless'); cell.append(node); }
      node.textContent = value;
      row.append(cell);
    });
    const actions = document.createElement('td');
    const revoke = document.createElement('button');
    revoke.type = 'button'; revoke.textContent = 'Revoke'; revoke.className = 'danger';
    revoke.disabled = !user.certificateIssued || user.certificateRevoked === true;
    revoke.addEventListener('click', () => openRevocation(user));
    actions.append(revoke); row.append(actions);
    return row;
  });
  if (!rows.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td'); cell.colSpan = 6;
    cell.textContent = query ? 'No users match your search.' : 'No users provisioned. Use the Create user form to get started.';
    row.append(cell); rows.push(row);
  }
  el('users').replaceChildren(...rows);
  el('directory-count').textContent = `${users.length} of ${inventory.users.length} users · Inventory only; secret contents are never read`;
}
async function refresh() {
  el('refresh').disabled = true;
  try {
    const response = await fetch('/admin/api/overview', { cache: 'no-store', signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw new Error(response.status === 403 ? 'Administrator certificate access was denied.' : `Server returned ${response.status}. Check the server logs.`);
    const data = await response.json(); inventory = data;
    el('user-count').textContent = data.users.length;
    el('credential-count').textContent = data.users.reduce((total, user) => total + user.credentialCount, 0);
    el('session-count').textContent = data.activeSessions;
    const minutes = Math.max(0, Math.floor((new Date(data.observedAt) - new Date(data.startedAt)) / 60000));
    el('uptime').textContent = minutes < 60 ? `${minutes}m` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
    el('started').textContent = `Started ${date(data.startedAt)}`;
    el('port').textContent = data.listenPort;
    el('lifetime').textContent = `${data.tokenLifetimeMinutes} minutes`;
    el('subject').textContent = data.certificateSubject;
    el('expiry').textContent = date(data.certificateExpiresAt);
    const days = Math.ceil((new Date(data.certificateExpiresAt) - new Date(data.observedAt)) / 86400000);
    el('status').className = days <= 30 ? 'error' : '';
    el('status').textContent = days <= 0 ? 'Server certificate has expired.' : days <= 30 ? `Server reachable · Certificate expires in ${days} days. Plan renewal.` : 'Server reachable · Inventory up to date';
    el('updated').textContent = `Updated ${date(data.observedAt)} · Refreshes every 30s`;
    renderUsers();
  } catch (error) {
    el('status').className = 'error';
    el('status').textContent = `Refresh failed. ${error.message} Displayed data may be stale.`;
  } finally { el('refresh').disabled = false; }
}
el('refresh').addEventListener('click', refresh);
el('search').addEventListener('input', renderUsers);
refresh();
setInterval(() => { if (!document.hidden && !el('refresh').disabled) refresh(); }, 30000);

async function mutate(url, body) {
  const response = await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-VFido-Admin': '1' },
    body: JSON.stringify(body), cache: 'no-store'
  });
  if (!response.ok) {
    const problem = await response.json().catch(() => null);
    throw new Error(problem?.detail || `Request failed (${response.status}).`);
  }
  return response;
}
const createForm = el('create-user');
createForm.elements.noPassword.addEventListener('change', () => {
  createForm.elements.loginPassword.disabled = createForm.elements.noPassword.checked;
  createForm.elements.loginPassword.required = !createForm.elements.noPassword.checked;
});
createForm.addEventListener('submit', async event => {
  event.preventDefault();
  const button = createForm.querySelector('button'); button.disabled = true;
  el('action-status').textContent = 'Creating user?';
  const username = createForm.elements.username.value;
  try {
    const response = await mutate('/admin/api/users', {
      username, caPassphrase: createForm.elements.caPassphrase.value,
      loginPassword: createForm.elements.loginPassword.value,
      pfxPassword: createForm.elements.pfxPassword.value,
      noPassword: createForm.elements.noPassword.checked
    });
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement('a'); link.href = url; link.download = `${username}.pfx`;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    createForm.reset(); createForm.elements.loginPassword.disabled = false; createForm.elements.loginPassword.required = true;
    el('action-status').textContent = `Created ${username}. PFX download started; a copy is also saved in the server user directory.`;
    await refresh();
  } catch (error) { el('action-status').textContent = error.message; }
  finally {
    createForm.elements.caPassphrase.value = ''; createForm.elements.loginPassword.value = ''; createForm.elements.pfxPassword.value = '';
    button.disabled = false;
  }
});
let revokingUser = null;
function openRevocation(user) {
  revokingUser = user;
  el('revoke-description').textContent = `Revoke the certificate for ${user.name}? Subsequent requests will be blocked immediately. Stored credentials will be retained. This cannot be undone from the dashboard.`;
  el('revoke-password-label').hidden = !user.revocationPasswordRequired;
  el('revoke-password').value = ''; el('revoke-error').textContent = '';
  el('revoke-dialog').showModal();
}
el('cancel-revoke').addEventListener('click', () => el('revoke-dialog').close());
el('revoke-dialog').addEventListener('close', () => { el('revoke-password').value = ''; });
el('revoke-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.target.querySelector('[type="submit"]'); button.disabled = true;
  try {
    await mutate(`/admin/api/users/${encodeURIComponent(revokingUser.name)}/revoke`, { pfxPassword: el('revoke-password').value });
    el('action-status').textContent = `Certificate for ${revokingUser.name} revoked.`;
    el('revoke-dialog').close(); await refresh();
  } catch (error) { el('revoke-error').textContent = error.message; }
  finally { button.disabled = false; el('revoke-password').value = ''; }
});
