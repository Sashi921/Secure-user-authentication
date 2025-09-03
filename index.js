
    const API = "http://localhost:5000";
    let token = "";

    async function signup() {
      const username = document.getElementById("signup-username").value;
      const password = document.getElementById("signup-password").value;

      const res = await fetch(API + "/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      document.getElementById("message").innerText = data.message;
    }

    async function login() {
      const username = document.getElementById("login-username").value;
      const password = document.getElementById("login-password").value;

      const res = await fetch(API + "/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      if (data.token) {
        token = data.token;
        document.getElementById("message").innerText = "Login successful!";
      } else {
        document.getElementById("message").innerText = data.message;
      }
    }

    async function accessProtected() {
      const res = await fetch(API + "/protected", {
        headers: { "Authorization": "Bearer " + token }
      });

      const data = await res.json();
      document.getElementById("message").innerText = data.message || "Access denied!";
    }
  