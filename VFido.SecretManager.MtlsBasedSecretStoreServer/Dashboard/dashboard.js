let inventory = null;
const el = id => document.getElementById(id);
const date = value => new Date(value).toLocaleString();
function renderUsers() {
  if (!inventory) return;
  const query = el('search').value.toLocaleLowerCase();
  const users = inventory.users.filter(user => user.name.toLocaleLowerCase().includes(query));
  const rows = users.map(user => {
    const row = document.createElement('tr');
    [user.name, user.passwordRequired ? 'Certificate + password' : 'Certificate only', user.credentialCount, user.activeSessions, user.certificateIssued ? 'PFX present' : 'No PFX file'].forEach((value, index) => {
      const cell = document.createElement('td');
      const node = index === 1 ? document.createElement('span') : cell;
      if (index === 1) { node.className = 'pill' + (user.passwordRequired ? '' : ' passwordless'); cell.append(node); }
      node.textContent = value;
      row.append(cell);
    });
    return row;
  });
  if (!rows.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td'); cell.colSpan = 5;
    cell.textContent = query ? 'No users match your search.' : 'No users provisioned. Use create-user on the server to get started.';
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
