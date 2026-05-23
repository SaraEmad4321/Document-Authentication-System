//Global variable
let currentUser = null; //stored the currently logged-in user; null means no user is logged in yet

//Page navigation

function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active')); //Hide all pages by removing 'active' class
  document.getElementById('page-' + name).classList.add('active'); //Show the selected page by adding 'active'
}

//Load users from server

async function loadUsers() { //fetch list of users from backend (/users)
  try {
    const res = await fetch('/users');
    const users = await res.json(); // Send get request and receive users as json
    ['login-user', 'sign-user', 'verify-user'].forEach(id => { //loop through all dropdowns (login, sign, verify)
      const sel = document.getElementById(id);
      const prev = sel.value; //get dropdown and remember selected value
      sel.innerHTML = id === 'login-user'
        ? '<option value="">— Choose user —</option>'
        : ''; //reset dropdown content; only login gets adefault option
      users.forEach(u => { //add each user as an option in dropdown
        const opt = document.createElement('option');
        opt.value = u;
        opt.textContent = u;
        sel.appendChild(opt);
      });
      if (prev) sel.value = prev; //restore previous selection
    });
  } catch (e) {
    console.error('Could not load users:', e);
  }
}

// Login
function doLogin() {
  const u = document.getElementById('login-user').value; //get selected username
  if (!u) { alert('Please select a user.'); return; } //prevent login without selecting user
  setCurrentUser(u);
  showPage('dashboard'); //save user and go to dashboard
}
//Register
async function doRegister() {
  const u = document.getElementById('reg-user').value.trim(); //get username input and remove spaces
  const statusEl = document.getElementById('reg-status');

  if (!u) {
    showRegStatus('error', 'Please enter a username.');
    return;
  }

  const btn = document.querySelector('#page-register .btn-full');
  btn.disabled = true; //disable button while processing
  btn.textContent = 'Generating keys…'; 

  try {
    const res = await fetch('/register', { //send POST request to backend
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u }) //send username as json
    });
    const data = await res.json(); //receive response from server

    if (data.ok) { //if registration successful
      await loadUsers(); // refresh dropdowns with the new user
      setCurrentUser(u.toLowerCase().trim().replace(/[^a-z0-9_-]/g, '')); //Auto login the new user
      showRegStatus('success', data.message);
      setTimeout(() => showPage('dashboard'), 900); //wait a bit then go to dashboard
    } else {
      showRegStatus('error', data.message);
    }
  } catch (e) {
    showRegStatus('error', 'Registration request failed.');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate keys & register →';
  }
}
//Registration status
function showRegStatus(type, msg) { //shows success or error message on registeration page
  const el = document.getElementById('reg-status');
  el.className = 'reg-status-banner ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}
//Set current user
function setCurrentUser(u) {
  currentUser = u; //save current user globally
  document.getElementById('dash-username').textContent = u; //display username in dashboard
  const signSel = document.getElementById('sign-user');
  const verifySel = document.getElementById('verify-user');
  if (signSel) signSel.value = u;
  if (verifySel) verifySel.value = u; //auto fill user in sign & verofy dropdowns
}

//Logout
function doLogout() {
  currentUser = null;
  showPage('home'); //Clear user & go back to home page
}

// Tabs in Dashboard

function switchTab(name, btn) { 
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active')); //remove active from all tabs
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active'); //add active to selected tab (used to switch between sign, verify, & how it work tabs)
  document.getElementById('tab-' + name).classList.add('active');
}

//File upload

function fileChosen(zoneId, input) {
  const zone = document.getElementById(zoneId);
  const label = document.getElementById(zoneId.replace('-zone', '-file-label'));
  if (input.files.length > 0) {
    label.textContent = '📎 ' + input.files[0].name; //show selected file name
    zone.style.borderColor = 'var(--accent)'; //highlight upload area
  }
}
//Drag and drop
document.addEventListener('DOMContentLoaded', () => { //run code when page loads
  loadUsers();

  document.querySelectorAll('.upload-zone').forEach(zone => {
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); }); //allowing dragging files over zone
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => {  //handle file drop
      e.preventDefault();
      zone.classList.remove('dragover');
      const inp = zone.querySelector('input[type="file"]');
      if (e.dataTransfer.files.length) {
        inp.files = e.dataTransfer.files; //assign fropped file to input
        fileChosen(zone.id, inp);
      }
    });
  });
});

//Status Messages

function showStatus(id, type, msg) {
  const el = document.getElementById(id);
  el.className = 'status-banner show ' + type;
  el.innerHTML = `<span class="status-icon">${type === 'success' ? '✔' : '✖'}</span> ${msg}`; //display success or error messages 
}

//Sign File

function submitSign() {
  const file = document.getElementById('sign-file').files[0]; //get selected file
  const signer = document.getElementById('sign-user').value;
  if (!file) { showStatus('sign-status', 'error', 'No file selected.'); return; }

  const fd = new FormData();
  fd.append('file', file);
  fd.append('signer', signer); //prepare data to send to backend

  fetch('/sign', { method: 'POST', body: fd }) //send file + signer to flask backend
    .then(r => r.text())
    .then(html => {
      const msg = extractMessage(html); //extract message from servr response
      const ok = msg.includes('✔') || msg.toLowerCase().includes('signed');
      showStatus('sign-status', ok ? 'success' : 'error', msg);
    })
    .catch(() => showStatus('sign-status', 'error', 'Request failed.'));
}

//Verify file

function submitVerify() { 
  const file = document.getElementById('verify-file').files[0];
  const vuser = document.getElementById('verify-user').value;
  if (!file) { showStatus('verify-status', 'error', 'No file selected.'); return; }

  const fd = new FormData();
  fd.append('file', file);
  fd.append('verify_user', vuser);

  fetch('/verify', { method: 'POST', body: fd })
    .then(r => r.text())
    .then(html => {
      const msg = extractMessage(html);
      const ok = msg.includes('✔') || msg.toUpperCase().includes('AUTHENTIC'); //check if verification succeeded
      showStatus('verify-status', ok ? 'success' : 'error', msg);

      const detail = document.getElementById('sig-details');
      if (ok) {
        detail.className = 'sig-detail show';
        detail.innerHTML = //show signature details
          `<span>ALGORITHM</span>  ECDSA / SECP256R1 + SHA-256<br>` +
          `<span>SIGNER   </span>  ${vuser}<br>` +
          `<span>STATUS   </span>  Signature verified ✔`;
      } else {
        detail.className = 'sig-detail';
      }
    })
    .catch(() => showStatus('verify-status', 'error', 'Request failed.'));
}
//Extract Message
function extractMessage(html) {
  const dmatch = html.match(/data-message="([^"]+)"/); 
  if (dmatch) return dmatch[1].trim(); //try to extract message from html attribute
  const ematch = html.match(/>([✔✖️][^<]{2,})</); //or extract message from visible text
  if (ematch) return ematch[1].trim();
  return 'Unknown response'; ///Fallback is nothing found
}