// ==================== GLOBAL CONFIG ====================
const API_BASE = window.location.origin;
const APP_CONFIG = {
  api: {
    adminLogin: `${API_BASE}/api/auth/admin/login`,
    employeeLogin: `${API_BASE}/api/auth/employee/login`,
    applyLeave: `${API_BASE}/api/leave/apply`,
    getMyRequests: `${API_BASE}/api/leave/my-requests`,
    getMyTracker: `${API_BASE}/api/leave/my-tracker`,
    getAllRequests: `${API_BASE}/api/leave/requests`,
    approveLeave: `${API_BASE}/api/leave/approve`,
    declineLeave: `${API_BASE}/api/leave/decline`,
    uploadProof: `${API_BASE}/api/leave/proof/upload`,
    downloadProof: `${API_BASE}/api/leave/proof/file`,
    reviewProof: `${API_BASE}/api/leave/proof/review`,
    getSettings: `${API_BASE}/api/settings/profile`,
    updateSettings: `${API_BASE}/api/settings/profile`,
    getEmployees: `${API_BASE}/api/admin/employees`,
    createEmployee: `${API_BASE}/api/admin/employees/create`,
    getEmployeeTracker: `${API_BASE}/api/admin/employees/leave-tracker`,
    updateEmployeeStatus: `${API_BASE}/api/admin/employees`,
    reassignEmployee: `${API_BASE}/api/admin/employees`,
    getPolicy: `${API_BASE}/api/admin/policy`,
    updatePolicy: `${API_BASE}/api/admin/policy`,
    getAudit: `${API_BASE}/api/admin/audit`,
    getAnalytics: `${API_BASE}/api/admin/analytics`,
    getNotifications: `${API_BASE}/api/notifications`,
    markNotificationRead: `${API_BASE}/api/notifications/read`,
    markAllNotificationsRead: `${API_BASE}/api/notifications/read-all`
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
  return email.includes("@") && password.length >= 8 && accessCode.length === 8;
}

function validateEmployee(form) {
  const email = form.querySelector("#emp-email").value.trim();
  const password = form.querySelector("#emp-pass").value.trim();
  return email.includes("@") && password.length >= 6;
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
      email: form.querySelector(role === "admin" ? "#admin-id" : "#emp-email").value,
      password: form.querySelector(role === "admin" ? "#admin-pass" : "#emp-pass").value,
    };

    if (role === "admin") {
      payload.accessCode = form.querySelector("#access-code").value;
    }

    const response = await fetch(
      role === "admin" ? APP_CONFIG.api.adminLogin : APP_CONFIG.api.employeeLogin,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }
    );

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

  const welcomeText = document.getElementById("welcome-text");
  if (welcomeText) {
    welcomeText.textContent = user.email.split("@")[0].toUpperCase();
  }
  const employeeId = user.employee_id || `EMP-${String(user.id || "").replace(/-/g, "").slice(0, 8).toUpperCase()}`;
  const employeeLabel = document.getElementById("employee-id-label");
  if (employeeLabel) employeeLabel.textContent = employeeId;
  const employeeIdField = document.getElementById("employee-id");
  if (employeeIdField) employeeIdField.value = employeeId;

  await loadSettings(user.id);
  await loadEmployeeLeaveTracker(user.id);
  await loadEmployeeLeaveRequests(user.id);
  await loadNotifications();
  setupNotificationUI();

  const leaveForm = document.getElementById("leave-form");
  if (leaveForm) {
    leaveForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await submitLeaveApplication(e, user);
    });
  }

  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", handleLogout);
  }
}

async function submitLeaveApplication(e, user) {
  const form = e.target;

  const payload = {
    leave_type: document.getElementById("leave-type").value,
    start_date: document.getElementById("start-date").value,
    end_date: document.getElementById("end-date").value,
    reason: document.getElementById("reason").value,
    user_id: user.id,
    employee_name: user.email,
    department: document.getElementById("department")?.value || "Not Specified"
  };

  try {
    const proofFile = document.getElementById("proof-file")?.files?.[0];
    const response = await fetch(APP_CONFIG.api.applyLeave, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      },
      body: JSON.stringify(payload)
    });

    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to submit application");

    if (proofFile) {
      await uploadProofDocument(result.id, proofFile);
    }

    alert("Leave application submitted successfully.");
    form.reset();
    await loadEmployeeLeaveRequests(user.id);
    await loadEmployeeLeaveTracker(user.id);
  } catch (error) {
    alert("Failed to submit leave application: " + error.message);
  }
}

async function loadEmployeeLeaveRequests(userId) {
  try {
    const response = await fetch(`${APP_CONFIG.api.getMyRequests}?user_id=${userId}`, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    if (!response.ok) throw new Error("Failed to load requests");

    const result = await response.json();
    const requests = result.data || [];
    const tableBody = document.getElementById("my-requests");
    if (!tableBody) return;

    tableBody.innerHTML = "";
    if (requests.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:20px;">No leave requests yet</td></tr>';
      return;
    }

    requests.forEach((request) => {
      const row = document.createElement("tr");
      const statusRaw = String(request.status || "").toLowerCase();
      const statusColor = statusRaw.startsWith("pending")
        ? "#f59e0b"
        : ({ approved: "#10b981", declined: "#ef4444" }[statusRaw] || "#9ca3af");

      row.innerHTML = `
        <td>${request.leave_type}</td>
        <td>${request.start_date} to ${request.end_date}</td>
        <td>${request.reason || "-"}</td>
        <td><span class="status-pill" style="background:${statusColor}20;color:${statusColor};">${formatStatusLabel(request.status)}</span></td>
        <td>${request.proof_status || "not_submitted"}</td>
        <td>
          <button class="btn-secondary" onclick="promptUploadProof('${request.id}')">Upload</button>
          <button class="btn-secondary" onclick="viewProofFile('${request.id}')">View</button>
        </td>
      `;
      tableBody.appendChild(row);
    });
  } catch (error) {
    console.error("Failed to load requests", error);
  }
}

async function loadEmployeeLeaveTracker(userId) {
  try {
    const response = await fetch(`${APP_CONFIG.api.getMyTracker}?user_id=${userId}`, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    if (!response.ok) throw new Error("Failed to load leave tracker");

    const result = await response.json();
    renderLeaveBalance(result.data?.by_type || {});
  } catch (error) {
    console.error("Failed to load leave tracker", error);
    renderLeaveBalance({});
  }
}

function renderLeaveBalance(byType) {
  const container = document.getElementById("leave-balance-cards");
  if (!container) return;

  const entries = Object.entries(byType || {});
  if (entries.length === 0) {
    container.innerHTML = '<p style="color:var(--text-secondary);">No leave data available yet.</p>';
    return;
  }

  const colors = ["var(--accent-blue)", "var(--accent-purple)", "#f59e0b", "#10b981", "#ef4444", "#06b6d4"];
  container.innerHTML = entries.map(([leaveType, info], idx) => {
    const quota = info.quota || 0;
    const approved = info.approved_days || 0;
    const pending = info.pending_days || 0;
    const remaining = info.remaining_days || 0;
    const percent = quota > 0 ? Math.min((approved / quota) * 100, 100) : 0;
    const color = colors[idx % colors.length];
    return `
      <div style="margin-bottom:20px;">
        <p style="color:var(--text-secondary);margin-bottom:6px;">${leaveType}</p>
        <div style="background:rgba(255,255,255,0.08);height:8px;border-radius:4px;">
          <div style="background:${color};height:100%;width:${percent}%;border-radius:4px;"></div>
        </div>
        <small style="color:var(--text-secondary);">
          Approved ${approved}/${quota} days, Pending ${pending}, Remaining ${remaining}
        </small>
      </div>
    `;
  }).join("");
}

function formatStatusLabel(statusRaw) {
  const status = String(statusRaw || "").toLowerCase();
  if (status.startsWith("pending_l") && status.includes("_of_")) {
    const parsed = status.replace("pending_l", "").split("_of_");
    if (parsed.length === 2) return `Pending L${parsed[0]}/${parsed[1]}`;
  }
  if (status === "pending") return "Pending";
  if (status === "approved") return "Approved";
  if (status === "declined") return "Declined";
  return statusRaw || "-";
}

// ==================== ADMIN DASHBOARD ====================

async function initializeAdminDashboard() {
  const user = JSON.parse(localStorage.getItem(APP_CONFIG.storageKeys.user));
  const token = localStorage.getItem(APP_CONFIG.storageKeys.token);

  if (!user || !token) {
    window.location.href = "index.html";
    return;
  }

  const welcomeText = document.getElementById("welcome-text");
  if (welcomeText) {
    welcomeText.textContent = user.email;
  }

  const managerId = user.manager_id || `MGR-${String(user.id || "").replace(/-/g, "").slice(0, 8).toUpperCase()}`;
  const managerLabel = document.getElementById("manager-id-label");
  if (managerLabel) managerLabel.textContent = managerId;
  const managerIdField = document.getElementById("manager-id");
  if (managerIdField) managerIdField.value = managerId;

  await loadSettings(user.id);
  await loadAllLeaveRequests();
  await loadManagedEmployees();
  await loadPolicy();
  await loadAnalytics();
  await loadAuditLogs();
  await loadNotifications();
  setupNotificationUI();

  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) logoutBtn.addEventListener("click", handleLogout);

  const refreshBtn = document.getElementById("refresh-btn");
  if (refreshBtn) refreshBtn.addEventListener("click", async () => {
    await loadAllLeaveRequests();
    await loadManagedEmployees();
  });
  const refreshAuditBtn = document.getElementById("refresh-audit-btn");
  if (refreshAuditBtn) refreshAuditBtn.addEventListener("click", loadAuditLogs);
  const refreshAnalyticsBtn = document.getElementById("refresh-analytics-btn");
  if (refreshAnalyticsBtn) refreshAnalyticsBtn.addEventListener("click", loadAnalytics);

  const createEmployeeForm = document.getElementById("create-employee-form");
  if (createEmployeeForm) {
    createEmployeeForm.addEventListener("submit", createEmployee);
  }
  const reloadPolicyBtn = document.getElementById("reload-policy-btn");
  if (reloadPolicyBtn) reloadPolicyBtn.addEventListener("click", loadPolicy);
  const savePolicyBtn = document.getElementById("save-policy-btn");
  if (savePolicyBtn) savePolicyBtn.addEventListener("click", savePolicy);
}

async function loadAllLeaveRequests() {
  try {
    const response = await fetch(APP_CONFIG.api.getAllRequests, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    if (!response.ok) throw new Error("Failed to load requests");

    const result = await response.json();
    const requests = result.data || [];

    const pendingCount = requests.filter((r) => String(r.status || "").startsWith("pending")).length;
    const approvedCount = requests.filter((r) => r.status === "approved").length;
    const declinedCount = requests.filter((r) => r.status === "declined").length;
    const pendingCountEl = document.getElementById("pending-count");
    const onLeaveCountEl = document.getElementById("on-leave-count");
    const criticalCountEl = document.getElementById("critical-count");
    if (pendingCountEl) pendingCountEl.textContent = String(pendingCount);
    if (onLeaveCountEl) onLeaveCountEl.textContent = String(approvedCount);
    if (criticalCountEl) criticalCountEl.textContent = String(declinedCount);

    const pendingRequests = requests.filter((r) => String(r.status || "").startsWith("pending"));
    const tableBody = document.getElementById("request-body");
    if (!tableBody) return;

    tableBody.innerHTML = "";
    if (pendingRequests.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:20px;">No pending requests</td></tr>';
      return;
    }

    pendingRequests.forEach((request) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td><strong>${request.employee_name}</strong><br><small>${request.department || "Not Specified"}</small></td>
        <td>${request.leave_type}</td>
        <td>${request.start_date} - ${request.end_date}</td>
        <td>${request.reason || "-"}</td>
        <td>${request.proof_status || "not_submitted"}</td>
        <td><span class="status-pill pending">${formatStatusLabel(request.status)}</span></td>
        <td class="action-cell">
          <button class="btn-secondary" onclick="viewProofFile('${request.id}')">View Proof</button>
          <button class="btn-secondary" onclick="reviewProof('${request.id}', 'verified')">Verify</button>
          <button class="btn-secondary" onclick="reviewProof('${request.id}', 'rejected')">Reject</button>
          <button class="approve-btn" onclick="approveLeave('${request.id}')" title="Approve"><i data-lucide="check"></i></button>
          <button class="decline-btn" onclick="declineLeave('${request.id}')" title="Decline"><i data-lucide="x"></i></button>
        </td>
      `;
      tableBody.appendChild(row);
    });

    if (window.lucide) lucide.createIcons();
  } catch (error) {
    console.error("Failed to load requests", error);
    const pendingCountEl = document.getElementById("pending-count");
    const onLeaveCountEl = document.getElementById("on-leave-count");
    const criticalCountEl = document.getElementById("critical-count");
    if (pendingCountEl) pendingCountEl.textContent = "0";
    if (onLeaveCountEl) onLeaveCountEl.textContent = "0";
    if (criticalCountEl) criticalCountEl.textContent = "0";
  }
}

async function approveLeave(requestId) {
  if (!confirm("Are you sure you want to approve this leave request?")) return;

  try {
    const response = await fetch(`${APP_CONFIG.api.approveLeave}/${requestId}`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
        "Content-Type": "application/json"
      }
    });

    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to approve leave");

    alert("Leave request approved successfully.");
    await loadAllLeaveRequests();
    await loadManagedEmployees();
  } catch (error) {
    alert("Error: " + error.message);
  }
}

async function declineLeave(requestId) {
  const reason = prompt("Enter reason for declining (optional):");

  try {
    const response = await fetch(`${APP_CONFIG.api.declineLeave}/${requestId}`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ reason: reason || "" })
    });

    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to decline leave");

    alert("Leave request declined.");
    await loadAllLeaveRequests();
    await loadManagedEmployees();
  } catch (error) {
    alert("Error: " + error.message);
  }
}

async function uploadProofDocument(requestId, file) {
  const formData = new FormData();
  formData.append("file", file);
  const response = await fetch(`${APP_CONFIG.api.uploadProof}/${requestId}`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
    },
    body: formData
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.message || "Failed to upload proof");
  return result.data;
}

function promptUploadProof(requestId) {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".pdf,.png,.jpg,.jpeg";
  input.onchange = async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    try {
      await uploadProofDocument(requestId, file);
      alert("Proof uploaded.");
      const user = JSON.parse(localStorage.getItem(APP_CONFIG.storageKeys.user) || "{}");
      if (document.body.classList.contains("employee-dashboard")) {
        await loadEmployeeLeaveRequests(user.id);
      } else {
        await loadAllLeaveRequests();
      }
    } catch (error) {
      alert("Error: " + error.message);
    }
  };
  input.click();
}

async function viewProofFile(requestId) {
  try {
    const response = await fetch(`${APP_CONFIG.api.downloadProof}/${requestId}`, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.message || "Failed to download proof");
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch (error) {
    alert("Error: " + error.message);
  }
}

async function reviewProof(requestId, decision) {
  const note = prompt(`Add note for ${decision} (optional):`) || "";
  try {
    const response = await fetch(`${APP_CONFIG.api.reviewProof}/${requestId}`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ decision, note })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to review proof");
    alert(`Proof ${decision}.`);
    await loadAllLeaveRequests();
  } catch (error) {
    alert("Error: " + error.message);
  }
}

async function loadManagedEmployees() {
  try {
    const response = await fetch(APP_CONFIG.api.getEmployeeTracker, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    if (!response.ok) throw new Error("Failed to load employees");

    const result = await response.json();
    const employees = result.data || [];
    const tableBody = document.getElementById("employees-body");
    if (!tableBody) return;

    tableBody.innerHTML = "";
    if (employees.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:20px;">No employees found</td></tr>';
      return;
    }

    employees.forEach((emp) => {
      const row = document.createElement("tr");
      const status = String(emp.status || "active").toLowerCase();
      const statusColor = status === "active" ? "#10b981" : "#ef4444";
      row.innerHTML = `
        <td>${emp.employee_name || "Unnamed Employee"}</td>
        <td>${emp.employee_id || "-"}</td>
        <td>${emp.email || "-"}</td>
        <td>${emp.department || "Not Specified"}</td>
        <td><span class="status-pill" style="background:${statusColor}20;color:${statusColor};">${status}</span></td>
        <td>${emp.totals?.approved_days ?? 0}</td>
        <td>${emp.totals?.pending_days ?? 0}</td>
        <td>${emp.totals?.remaining_days ?? 0}</td>
        <td>
          <button class="btn-secondary" onclick="toggleEmployeeStatus('${emp.employee_id}', '${status}')">${status === "active" ? "Deactivate" : "Activate"}</button>
          <button class="btn-secondary" onclick="reassignEmployee('${emp.employee_id}')">Reassign</button>
        </td>
      `;
      tableBody.appendChild(row);
    });
  } catch (error) {
    console.error("Failed to load employees", error);
  }
}

async function createEmployee(e) {
  e.preventDefault();
  const employeeId = document.getElementById("new-employee-id").value.trim().toUpperCase();
  if (!employeeId.startsWith("EMP-")) {
    alert("Employee ID must start with EMP-");
    return;
  }
  const payload = {
    full_name: document.getElementById("new-employee-name").value.trim(),
    department: document.getElementById("new-employee-department").value.trim(),
    email: document.getElementById("new-employee-email").value.trim(),
    password: document.getElementById("new-employee-password").value,
    employee_id: employeeId
  };

  try {
    const response = await fetch(APP_CONFIG.api.createEmployee, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to create employee");

    alert(`Employee created: ${result.data.email}`);
    e.target.reset();
    await loadManagedEmployees();
  } catch (error) {
    alert("Error: " + error.message);
  }
}

async function toggleEmployeeStatus(employeeId, currentStatus) {
  const nextStatus = currentStatus === "active" ? "inactive" : "active";
  if (!confirm(`Set ${employeeId} to ${nextStatus}?`)) return;
  try {
    const response = await fetch(`${APP_CONFIG.api.updateEmployeeStatus}/${employeeId}/status`, {
      method: "PATCH",
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ status: nextStatus })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to update status");
    alert(`Employee ${employeeId} is now ${nextStatus}.`);
    await loadManagedEmployees();
  } catch (error) {
    alert("Error: " + error.message);
  }
}

async function reassignEmployee(employeeId) {
  const newManagerId = (prompt("Enter new manager ID (MGR-XXXXXXXX):") || "").trim().toUpperCase();
  if (!newManagerId) return;
  if (!newManagerId.startsWith("MGR-")) {
    alert("Manager ID must start with MGR-");
    return;
  }
  try {
    const response = await fetch(`${APP_CONFIG.api.reassignEmployee}/${employeeId}/reassign`, {
      method: "PATCH",
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ manager_id: newManagerId })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to reassign employee");
    alert(`Employee ${employeeId} reassigned to ${newManagerId}.`);
    await loadManagedEmployees();
  } catch (error) {
    alert("Error: " + error.message);
  }
}

async function loadPolicy() {
  const policyArea = document.getElementById("policy-json");
  if (!policyArea) return;
  try {
    const response = await fetch(APP_CONFIG.api.getPolicy, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to load policy");
    policyArea.value = JSON.stringify(result.data, null, 2);
  } catch (error) {
    alert("Policy load failed: " + error.message);
  }
}

async function savePolicy() {
  const policyArea = document.getElementById("policy-json");
  if (!policyArea) return;
  let payload;
  try {
    payload = JSON.parse(policyArea.value);
  } catch (_e) {
    alert("Invalid JSON format in policy editor.");
    return;
  }

  try {
    const response = await fetch(APP_CONFIG.api.updatePolicy, {
      method: "PUT",
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to save policy");
    alert("Leave policy updated.");
    policyArea.value = JSON.stringify(result.data, null, 2);
  } catch (error) {
    alert("Policy save failed: " + error.message);
  }
}

async function loadAuditLogs() {
  const tableBody = document.getElementById("audit-body");
  if (!tableBody) return;
  try {
    const response = await fetch(`${APP_CONFIG.api.getAudit}?limit=200`, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to load audit logs");
    const logs = result.data || [];
    tableBody.innerHTML = "";
    if (!logs.length) {
      tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 20px;">No audit events yet</td></tr>';
      return;
    }
    logs.forEach((entry) => {
      const row = document.createElement("tr");
      const details = JSON.stringify(entry.details || {});
      row.innerHTML = `
        <td>${entry.timestamp || "-"}</td>
        <td>${entry.event_type || "-"}</td>
        <td>${entry.actor_role || "-"}: ${entry.actor_id || "-"}</td>
        <td><small>${details}</small></td>
      `;
      tableBody.appendChild(row);
    });
  } catch (error) {
    tableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; padding: 20px;">Failed to load audit logs: ${error.message}</td></tr>`;
  }
}

async function loadAnalytics() {
  try {
    const response = await fetch(APP_CONFIG.api.getAnalytics, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to load analytics");
    const data = result.data || {};
    const summary = data.summary || {};
    const monthly = data.monthly_trend || {};
    const topAbsent = data.top_absent_employees || [];

    const totalEl = document.getElementById("report-total-requests");
    const rateEl = document.getElementById("report-approval-rate");
    const avgEl = document.getElementById("report-avg-approval-time");
    if (totalEl) totalEl.textContent = String(summary.total_requests || 0);
    if (rateEl) rateEl.textContent = `${summary.approval_rate_percent || 0}%`;
    if (avgEl) avgEl.textContent = `${summary.avg_approval_time_hours || 0}h`;

    const monthlyBody = document.getElementById("monthly-trend-body");
    if (monthlyBody) {
      monthlyBody.innerHTML = "";
      const monthKeys = Object.keys(monthly).sort();
      if (!monthKeys.length) {
        monthlyBody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:20px;">No monthly data</td></tr>';
      } else {
        monthKeys.forEach((m) => {
          const row = monthly[m] || {};
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>${m}</td>
            <td>${row.approved || 0}</td>
            <td>${row.pending || 0}</td>
            <td>${row.declined || 0}</td>
          `;
          monthlyBody.appendChild(tr);
        });
      }
    }

    const topBody = document.getElementById("top-absent-body");
    if (topBody) {
      topBody.innerHTML = "";
      if (!topAbsent.length) {
        topBody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:20px;">No employee data</td></tr>';
      } else {
        topAbsent.forEach((emp) => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>${emp.employee_name || "Unnamed Employee"}</td>
            <td>${emp.approved_days || 0}</td>
            <td>${emp.pending_days || 0}</td>
            <td>${emp.declined_days || 0}</td>
          `;
          topBody.appendChild(tr);
        });
      }
    }
  } catch (error) {
    const monthlyBody = document.getElementById("monthly-trend-body");
    const topBody = document.getElementById("top-absent-body");
    if (monthlyBody) monthlyBody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:20px;">${error.message}</td></tr>`;
    if (topBody) topBody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:20px;">${error.message}</td></tr>`;
  }
}

// ==================== SETTINGS ====================

async function loadSettings(userId) {
  try {
    const response = await fetch(`${APP_CONFIG.api.getSettings}?user_id=${userId}`, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });

    if (!response.ok) return;
    const result = await response.json();
    if (!result.data) return;

    const fullName = document.getElementById("full-name");
    const phone = document.getElementById("phone");
    const department = document.getElementById("department");
    const assignedManagerField = document.getElementById("assigned-manager-id");
    const managerIdField = document.getElementById("manager-id");
    const employeeIdField = document.getElementById("employee-id");
    const employeeLabel = document.getElementById("employee-id-label");

    if (fullName) fullName.value = result.data.full_name || "";
    if (phone) phone.value = result.data.phone || "";
    if (department) department.value = result.data.department || "";
    if (assignedManagerField) assignedManagerField.value = result.data.assigned_manager_id || "";
    if (managerIdField) managerIdField.value = result.data.manager_id || managerIdField.value;
    if (employeeIdField) employeeIdField.value = result.data.employee_id || employeeIdField.value;
    if (employeeLabel) employeeLabel.textContent = result.data.employee_id || employeeLabel.textContent;
  } catch (error) {
    console.error("Failed to load settings", error);
  }
}

async function saveSettings(userId) {
  try {
    const payload = {
      user_id: userId,
      full_name: document.getElementById("full-name")?.value || "",
      phone: document.getElementById("phone")?.value || "",
      department: document.getElementById("department")?.value || "",
      assigned_manager_id: document.getElementById("assigned-manager-id")?.value || ""
    };

    const response = await fetch(APP_CONFIG.api.updateSettings, {
      method: "PUT",
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to save settings");
    alert("Settings updated successfully.");
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

function setupNotificationUI() {
  const openBtn = document.getElementById("open-notifications");
  const panel = document.getElementById("notification-panel");
  const closeBtn = document.getElementById("close-notifications-btn");
  const markAllBtn = document.getElementById("mark-all-read-btn");
  if (openBtn && panel) {
    openBtn.onclick = () => {
      panel.style.display = panel.style.display === "none" ? "block" : "none";
    };
  }
  if (closeBtn && panel) closeBtn.onclick = () => { panel.style.display = "none"; };
  if (markAllBtn) markAllBtn.onclick = markAllNotificationsRead;
}

async function loadNotifications() {
  const list = document.getElementById("notification-list");
  const badge = document.getElementById("notification-badge");
  try {
    const response = await fetch(`${APP_CONFIG.api.getNotifications}?limit=50`, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to load notifications");
    const items = result.data || [];
    const unread = result.unread_count || 0;
    if (badge) badge.textContent = String(unread);
    if (!list) return;
    if (!items.length) {
      list.innerHTML = '<p style="color: var(--text-secondary);">No notifications</p>';
      return;
    }
    list.innerHTML = items.map((n) => `
      <div style="padding:10px;border-bottom:1px solid var(--border-color);">
        <div style="display:flex;justify-content:space-between;gap:8px;">
          <strong>${n.title || "Notification"}</strong>
          <small>${n.read ? "Read" : "Unread"}</small>
        </div>
        <div style="font-size:0.9rem;margin-top:4px;">${n.message || ""}</div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px;">
          <small style="color:var(--text-secondary);">${n.timestamp || ""}</small>
          ${n.read ? "" : `<button class="btn-secondary" onclick="markNotificationRead('${n.id}')">Mark Read</button>`}
        </div>
      </div>
    `).join("");
  } catch (error) {
    if (list) list.innerHTML = `<p style="color:#ef4444;">${error.message}</p>`;
  }
}

async function markNotificationRead(notificationId) {
  try {
    const response = await fetch(`${APP_CONFIG.api.markNotificationRead}/${notificationId}`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to mark as read");
    await loadNotifications();
  } catch (error) {
    alert("Error: " + error.message);
  }
}

async function markAllNotificationsRead() {
  try {
    const response = await fetch(APP_CONFIG.api.markAllNotificationsRead, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${localStorage.getItem(APP_CONFIG.storageKeys.token)}`
      }
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Failed to mark all read");
    await loadNotifications();
  } catch (error) {
    alert("Error: " + error.message);
  }
}

// ==================== INITIALIZATION ====================

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".login-panel").forEach((form) => {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      handleSubmit(form);
    });
  });

  if (document.body.classList.contains("admin-dashboard")) {
    initializeAdminDashboard();
  } else if (document.body.classList.contains("employee-dashboard")) {
    initializeEmployeeDashboard();
  }
});
