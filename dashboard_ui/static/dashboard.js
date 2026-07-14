function bytesLabel(bytes) {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function switchTab(name) {
  document.querySelectorAll(".tab-btn").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(t => t.classList.remove("active"));
  document.querySelector(`.tab-btn[onclick*="${name}"]`).classList.add("active");
  document.getElementById(`panel-${name}`).classList.add("active");
}

async function refreshDashboard() {
  try {
    const [bucketResp, quarantineResp] = await Promise.all([
      fetch("/api/aws/buckets").then(r => r.json()),
      fetch("/api/aws/quarantine-files?max_items=50").then(r => r.json()),
    ]);

    const buckets = bucketResp.buckets;
    const quarantine = quarantineResp;

    if (buckets.staging) {
      document.getElementById("stagingCount").innerText = buckets.staging.object_count;
      document.getElementById("stagingSize").innerText = bytesLabel(buckets.staging.size_bytes);
    }
    if (buckets.clean) {
      document.getElementById("cleanCount").innerText = buckets.clean.object_count;
      document.getElementById("cleanSize").innerText = bytesLabel(buckets.clean.size_bytes);
    }
    if (buckets.quarantine) {
      document.getElementById("quarantineCount").innerText = buckets.quarantine.object_count;
      document.getElementById("quarantineSize").innerText = bytesLabel(buckets.quarantine.size_bytes);
    }

    const staging = buckets.staging?.object_count || 0;
    const clean = buckets.clean?.object_count || 0;
    const q = buckets.quarantine?.object_count || 0;
    document.getElementById("totalProcessed").innerText = clean + q;
    document.getElementById("totalThreats").innerText = q;
    document.getElementById("throughputRate").innerText = `${q + clean} total files processed`;

    renderQuarantineTable(quarantine);
  } catch (e) {
    console.error("Refresh failed:", e);
  }

  refreshSftpStatus();
  refreshSftpUsers();
}

async function refreshSftpStatus() {
  try {
    const r = await fetch("/api/sftp/status");
    const data = await r.json();
    if (data.status === "online") {
      document.getElementById("sftpStatusText").innerText = "Online";
      document.getElementById("sftpStatusText").style.color = "#16a34a";
      document.getElementById("sftpVersion").innerText = `v${data.version} · ${data.active_connections} active connections`;
      document.getElementById("activePartners").innerText = data.total_users;
      document.getElementById("healthSftp").innerText = `v${data.version} · Online`;
    } else {
      document.getElementById("sftpStatusText").innerText = "Offline";
      document.getElementById("sftpStatusText").style.color = "#dc2626";
      document.getElementById("sftpVersion").innerText = "Unreachable";
    }
  } catch (e) {
    document.getElementById("sftpStatusText").innerText = "Offline";
    document.getElementById("sftpStatusText").style.color = "#dc2626";
    document.getElementById("sftpVersion").innerText = "Connection error";
  }
}

async function refreshSftpUsers() {
  try {
    const r = await fetch("/api/sftp/users");
    const data = await r.json();
    const table = document.getElementById("sftpUsersTable");
    if (!table) return;
    table.innerHTML = "";
    if (!data.users || data.users.length === 0) {
      table.innerHTML = `<tr><td colspan="6">No partners provisioned.</td></tr>`;
      return;
    }
    for (const u of data.users) {
      const keys = u.public_keys ? u.public_keys.length : 0;
      const s3config = u.filesystem?.s3config || {};
      const company = (u.username || "").replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase());
      table.innerHTML += `<tr>
        <td><code>${u.username}</code></td>
        <td><strong>${company}</strong></td>
        <td>${u.home_dir || "/"}</td>
        <td>s3://${s3config.bucket || "-"}/${s3config.key_prefix || ""}</td>
        <td>${keys} SSH key${keys !== 1 ? 's' : ''} ${u.has_password ? '+ password' : ''}</td>
        <td><span class="badge ACTIVE">Active</span></td>
      </tr>`;
    }
  } catch (e) {
    const table = document.getElementById("sftpUsersTable");
    if (table) table.innerHTML = `<tr><td colspan="6">Error loading partners.</td></tr>`;
  }
}

function renderQuarantineTable(quarantine) {
  const table = document.getElementById("quarantineTable");
  if (!table) return;
  table.innerHTML = "";
  if (!quarantine || !quarantine.files || quarantine.files.length === 0) {
    table.innerHTML = `<tr><td colspan="7">No threats detected. All files clean.</td></tr>`;
    return;
  }
  for (const file of quarantine.files) {
    const tags = file.tags || {};
    const threat = tags["scan:threat-name"] || "UNKNOWN";
    const company = tags["source:company"] || "UNKNOWN";
    const batch = tags["migration:batch-id"] || "-";
    const review = tags["review:status"] || "PENDING";
    const date = file.last_modified ? file.last_modified.slice(0, 19).replace("T", " ") : "-";
    table.innerHTML += `<tr>
      <td title="${file.key}">${file.key.split("/").pop()}</td>
      <td>${bytesLabel(file.size)}</td>
      <td><span class="badge INFECTED">${threat}</span></td>
      <td>${company}</td>
      <td>${batch}</td>
      <td><span class="badge ${review}">${review}</span></td>
      <td>${date}</td>
    </tr>`;
  }
}

refreshDashboard();
setInterval(refreshDashboard, 10000);
