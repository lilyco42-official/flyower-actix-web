const API_BASE = '';

function getToken() {
  return localStorage.getItem('token');
}

async function request(url, options = {}) {
  const res = await fetch(API_BASE + url, {
    headers: {
      'Content-Type': 'application/json',
      ...(getToken() && { Authorization: 'Bearer ' + getToken() })
    },
    ...options
  });

  return res.json();
}