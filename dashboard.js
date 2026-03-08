// ==================== GLOBAL CONFIG ====================
const APP_CONFIG = {
  api: {
    adminLogin: "http://127.0.0.1:5000/api/auth/admin/login",
    employeeLogin: "http://127.0.0.1:5000/api/auth/employee/login",
    applyLeave: "http://127.0.0.1:5000/api/leave/apply",
    getMyRequests: "http://127.0.0.1:5000/api/leave/my-requests",
    getAllRequests: "http://127.0.0.1:5000/api/leave/requests",
    approveLeave: "http://127.0.0.1:5000/api/leave/approve",
    declineLeave: "http://127.0.0.1:5000/api/leave/decline",
    getSettings: "http://127.0.0.1:5000/api/settings/profile",
    updateSettings: "http://127.0.0.1:5000/api/settings/profile",
    getDashboardStats: "http://127.0.0.1:5000/api/dashboard/stats",
    getNotificationSettings: "http://127.0.0.1:5000/api/settings/notifications",
    updateNotificationSettings: "http://127.0.0.1:5000/api/settings/notifications"
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

// ==================== AUTHENTICATION ====================

function validateAdmin(form) {
    const email = form.querySelector("#admin-id").value.trim();
    const password = form.querySelector("#admin-pass").value.trim();
    const accessCode = form.querySelector("#access-code").value.trim();
    return email.includes('@') && password.length >= 8 && accessCode.length === 8;
}

function validateEmployee(form) {
    const email = form.querySelector("#emp-email").value.trim();
    const password = form.querySelector("#emp-pass").value.trim();
    return email.includes('@') && password.length >= 6;
}

async function handleSubmit(form) {
  const role = form.dataset.role;
  const submitBtn = form.querySelector(".submit-btn");
  
  if (role === "admin" && !validateAdmin(form)) {
      alert("Please check your credentials. Access code must be 8 digits.");
      return;
  }

  if (role === "employee" && !validateEmployee(form)) {
      alert("Please enter valid credentials.");
      return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = "Connecting...";

  try {
    const payload = {
      email: form.querySelector(role === 'admin' ? "#admin-id" : "#emp-email").value,
      password: form.querySelector(role === 'admin' ? "#admin-pass" : "#emp-pass").value,
    };

    if (role === 'admin') {
        payload.accessCode = form.querySelector("#access-code").value;
    }

    const response = await fetch(role === 'admin' ? APP_CONFIG.api.adminLogin : APP_CONFIG.api.employeeLogin, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message || "Login failed");

    localStorage.setItem(APP_CONFIG.storageKeys.token, data.token);
    localStorage.setItem(APP_CONFIG.storageKeys.user, JSON.stringify(data.user));
    
    window.location.href = APP_CONFIG.redirect[role];

  } catch (error) {
    alert(error.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Sign In";
  }
}

// ==================== EMPLOYEE DASHBOARD ====================

async function initializeEmployeeDashboard() {
    const user = JSON.parse(localStorage.getItem(APP_CONFIG.storageKeys.user));
    const token = localStorage.getItem(APP_CONFIG.storageKeys.token);
    
    if (!user || !token) {
        window.location.href = "index.html";
        return;
    }

    // Update welcome message
    const welcomeText = document.getElementById('welcome-text');
    if (welcomeText) {
        welcomeText.textContent = user.email.split('@')[0].toUpperCase();
    }

    // Load employee's leave requests
    await loadEmployeeLeaveRequests(user.id);

    // Handle leave form submission
    const leaveForm = document.getElementById('leave-form');
    if (leaveForm) {
        leaveForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await submitLeaveApplication(e, user);
        });
    }

    // Logout handler
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
}

async function submitLeaveApplication(e, user) {
    e.preventDefault();
    const form = e.target;

    const payload = {
        leave_type: document.getElementById('leave-type').value,
        start_date: document.getElementById('start-date').value,
        end_date: document.getElementById('end-date').value,
        reason: document.getElementById('reason').value,
        user_id: user.id,
        employee_name: user.email,
        department: "IT Department"
    };

    try {
        const response = await fetch(APP_CONFIG.api.applyLeave, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) throw new Error("Failed to submit application");

        alert("Leave application submitted successfully!");
        form.reset();
        await loadEmployeeLeaveRequests(user.id);
    } catch (error) {
        console.error("Submission failed", error);
        alert("Failed to submit leave application: " + error.message);
    }
}

async function loadEmployeeLeaveRequests(userId) {
    try {
        const response = await fetch(`${APP_CONFIG.api.getMyRequests}?user_id=${userId}`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
            }
        });

        if (!response.ok) throw new Error("Failed to load requests");

        const result = await response.json();
        const requests = result.data || [];

        const tableBody = document.getElementById('my-requests');
        if (!tableBody) return;

        tableBody.innerHTML = '';

        if (requests.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 20px;">No leave requests yet</td></tr>';
            return;
        }

        requests.forEach(request => {
            const row = document.createElement('tr');
            const statusColor = {
                'approved': '#10b981',
                'declined': '#ef4444',
                'pending': '#f59e0b'
            }[request.status];

            row.innerHTML = `
                <td>${request.leave_type}</td>
                <td>${request.start_date} to ${request.end_date}</td>
                <td><span class="status-pill ${request.status}" style="background: ${statusColor}20; color: ${statusColor};">${request.status.charAt(0).toUpperCase() + request.status.slice(1)}</span></td>
            `;
            tableBody.appendChild(row);
        });
    } catch (error) {
        console.error("Failed to load requests", error);
    }
}

// ==================== ADMIN DASHBOARD ====================

async function initializeAdminDashboard() {
    const user = JSON.parse(localStorage.getItem(APP_CONFIG.storageKeys.user));
    const token = localStorage.getItem(APP_CONFIG.storageKeys.token);
    
    if (!user || !token) {
        window.location.href = "index.html";
        return;
    }

    // Update welcome message
    const welcomeText = document.getElementById('welcome-text');
    if (welcomeText) {
        welcomeText.textContent = user.email;
    }

    // Load all leave requests
    await loadAllLeaveRequests();

    // Logout handler
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }

    // Refresh button
    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadAllLeaveRequests);
    }
}

async function loadAllLeaveRequests() {
    try {
        const response = await fetch(APP_CONFIG.api.getAllRequests, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
            }
        });

        if (!response.ok) throw new Error("Failed to load requests");

        const result = await response.json();
        const requests = result.data || [];

        // Filter only pending requests for the table
        const pendingRequests = requests.filter(r => r.status === 'pending');

        const tableBody = document.getElementById('request-body');
        if (!tableBody) return;

        tableBody.innerHTML = '';

        if (pendingRequests.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px;">No pending requests</td></tr>';
            return;
        }

        pendingRequests.forEach(request => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong>${request.employee_name}</strong><br><small>${request.department || 'Not Specified'}</small></td>
                <td>${request.leave_type}</td>
                <td>${request.start_date} - ${request.end_date}</td>
                <td>${request.reason}</td>
                <td><span class="status-pill pending">Pending</span></td>
                <td class="action-cell">
                    <button class="approve-btn" onclick="approveLeave('${request.id}')" title="Approve"><i data-lucide="check"></i></button>
                    <button class="decline-btn" onclick="declineLeave('${request.id}')" title="Decline"><i data-lucide="x"></i></button>
                </td>
            `;
            tableBody.appendChild(row);
        });

        // Reinitialize lucide icons
        if (window.lucide) lucide.createIcons();
    } catch (error) {
        console.error("Failed to load requests", error);
    }
}

async function approveLeave(requestId) {
    if (!confirm("Are you sure you want to approve this leave request?")) return;

    try {
        const response = await fetch(`${APP_CONFIG.api.approveLeave}/${requestId}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) throw new Error("Failed to approve leave");

        alert("Leave request approved successfully!");
        await loadAllLeaveRequests();
    } catch (error) {
        alert("Error: " + error.message);
    }
}

async function declineLeave(requestId) {
    const reason = prompt("Enter reason for declining (optional):");
    
    try {
        const response = await fetch(`${APP_CONFIG.api.declineLeave}/${requestId}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ reason: reason || "" })
        });

        if (!response.ok) throw new Error("Failed to decline leave");

        alert("Leave request declined!");
        await loadAllLeaveRequests();
    } catch (error) {
        alert("Error: " + error.message);
    }
}

// ==================== SETTINGS ====================

async function loadSettings(userId, role) {
    try {
        const response = await fetch(`${APP_CONFIG.api.getSettings}?user_id=${userId}`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
            }
        });

        if (response.ok) {
            const result = await response.json();
            if (result.data) {
                document.getElementById('full-name').value = result.data.full_name || '';
                document.getElementById('phone').value = result.data.phone || '';
                document.getElementById('department').value = result.data.department || '';
            }
        }
    } catch (error) {
        console.error("Failed to load settings", error);
    }
}

async function saveSettings(userId) {
    try {
        const payload = {
            user_id: userId,
            full_name: document.getElementById('full-name').value,
            phone: document.getElementById('phone').value,
            department: document.getElementById('department').value
        };

        const response = await fetch(APP_CONFIG.api.updateSettings, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) throw new Error("Failed to save settings");

        alert("Settings updated successfully!");
    } catch (error) {
        alert("Error: " + error.message);
    }
}

// ==================== GLOBAL HANDLERS ====================

function handleLogout() {
    localStorage.removeItem(APP_CONFIG.storageKeys.token);
    localStorage.removeItem(APP_CONFIG.storageKeys.user);
    window.location.href = "index.html";
}

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', () => {
    // Login page handlers
    document.querySelectorAll(".login-panel").forEach(form => {
        form.addEventListener("submit", (e) => {
            e.preventDefault();
            handleSubmit(form);
        });
    });

    // Dashboard initialization
    if (document.body.classList.contains('admin-dashboard')) {
        initializeAdminDashboard();
    } else if (document.body.classList.contains('employee-dashboard')) {
        initializeEmployeeDashboard();
    }
});