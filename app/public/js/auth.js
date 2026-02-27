async function login() {
  const login = username.value;
  const password = passwordInput.value;

  const data = await request('/sign_in', {
    method: 'POST',
    body: JSON.stringify({ login, password })
  });

  if (data.token) {
    localStorage.setItem('token', data.token);
    location.href = '/';
  } else {
    alert(data.message);
  }
}