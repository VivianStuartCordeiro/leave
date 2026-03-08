const APP_CONFIG = {
  api: {
    adminLogin: "http://127.0.0.1:5000/api/auth/admin/login",
    employeeLogin: "http://127.0.0.1:5000/api/auth/employee/login",
  },
  redirect: {
    admin: "admin-dashboard.html",
    employee: "employee-dashboard.html",
  },
  storageKeys: {
    token: "leaveflow_token",
    user: "leaveflow_user",
  }
};

// --- VALIDATION ---
function validateAdmin(form) {
    const email = form.querySelector("#admin-id").value.trim();
    const password = form.querySelector("#admin-pass").value.trim();
    const accessCode = form.querySelector("#access-code").value.trim();
    return email.includes('@') && password.length >= 8 && accessCode.length === 8;
}

// --- CORE HANDLER ---
async function handleSubmit(form) {
  const role = form.dataset.role;
  const submitBtn = form.querySelector(".submit-btn");
  
  if (role === "admin" && !validateAdmin(form)) {
      alert("Please check your credentials.");
      return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = "Connecting...";

  try {
    const payload = {
      email: form.querySelector(role === 'admin' ? "#admin-id" : "#emp-email").value,
      password: form.querySelector(role === 'admin' ? "#admin-pass" : "#emp-pass").value,
      accessCode: role === 'admin' ? form.querySelector("#access-code").value : null
    };

    const response = await fetch(role === 'admin' ? APP_CONFIG.api.adminLogin : APP_CONFIG.api.employeeLogin, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message || "Login failed");

    // SAVE DATA TO LOCAL STORAGE
    localStorage.setItem(APP_CONFIG.storageKeys.token, data.token);
    localStorage.setItem(APP_CONFIG.storageKeys.user, JSON.stringify(data.user));
    
    // REDIRECT AFTER SAVING
    window.location.href = APP_CONFIG.redirect[role];

  } catch (error) {
    alert(error.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Sign In";
  }
}

document.querySelectorAll(".login-panel").forEach(form => {
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    handleSubmit(form);
  });
});