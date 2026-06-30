let durationChart = null;
let statusChart = null;

function secondsLabel(value) {
  const numeric = Number(value || 0);
  if (numeric <= 0) return "0 sec";
  if (numeric < 60) return `${numeric} sec`;
  return `${Math.round(numeric / 60)} min`;
}

function statusBadge(status) {
  return `<span class="badge ${status}">${status}</span>`;
}

async function startEnterpriseScan() {
  const confirmed = confirm("Start a 5 × 100 MB enterprise performance scan? This uploads large AWS S3 test files.");
  if (!confirmed) return;

  const response = await fetch("/api/start-scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      file_count: 5,
      file_size_mb: 100,
      wait_timeout_seconds: 1800,
      poll_seconds: 10
    })
  });

  const data = await response.json();
  alert(`Enterprise scan started. Run ID: ${data.run_id}`);
  refreshDashboard();
}

async function refreshDashboard() {
  const response = await fetch("/api/scan-runs");
  const data = await response.json();
  const metrics = data.metrics;
  const runs = data.runs;

  document.getElementById("totalRuns").innerText = metrics.total_runs;
  document.getElementById("totalFiles").innerText = metrics.total_files;
  document.getElementById("totalSize").innerText = `${metrics.total_size_mb} MB`;
  document.getElementById("avgDuration").innerText = secondsLabel(metrics.avg_duration_seconds);
  document.getElementById("throughput").innerText = `${metrics.throughput_mb_per_min} MB/min`;

  renderTable(runs);
  renderLogs(runs);
  renderCharts(runs);
}

function renderTable(runs) {
  const table = document.getElementById("runsTable");
  table.innerHTML = "";

  if (!runs || runs.length === 0) {
    table.innerHTML = `<tr><td colspan="9">No scan runs yet. Click "Run 5 × 100 MB Test".</td></tr>`;
    return;
  }

  for (const run of runs) {
    table.innerHTML += `
      <tr>
        <td>${run.run_id}</td>
        <td>${statusBadge(run.status)}</td>
        <td>${Number(run.file_count || 0) * 2}</td>
        <td>${run.file_size_mb} MB</td>
        <td>${run.total_size_mb} MB</td>
        <td>${secondsLabel(run.duration_seconds)}</td>
        <td>${run.started_at}</td>
        <td>${run.completed_at}</td>
        <td>${run.return_code === null ? "-" : run.return_code}</td>
      </tr>`;
  }
}

function renderLogs(runs) {
  const logs = document.getElementById("latestLogs");
  if (!runs || runs.length === 0) {
    logs.innerText = "No run logs available yet.";
    return;
  }

  const latest = runs[0];
  logs.innerText = `
Run ID: ${latest.run_id}
Status: ${latest.status}
Command: FILE_COUNT=${latest.file_count} FILE_SIZE_MB=${latest.file_size_mb} WAIT_TIMEOUT_SECONDS=${latest.wait_timeout_seconds} POLL_SECONDS=${latest.poll_seconds} ./scripts/performance_large_scan_aws.sh

STDOUT:
${latest.stdout || "-"}

STDERR:
${latest.stderr || "-"}
`.trim();
}

function renderCharts(runs) {
  const sortedRuns = [...(runs || [])].reverse();
  const labels = sortedRuns.map((run) => run.run_id);
  const durations = sortedRuns.map((run) => Number(run.duration_seconds || 0));

  const statusCounts = { COMPLETED: 0, RUNNING: 0, QUEUED: 0, FAILED: 0, TIMEOUT: 0 };
  for (const run of runs || []) {
    if (statusCounts[run.status] === undefined) statusCounts[run.status] = 0;
    statusCounts[run.status] += 1;
  }

  if (durationChart) durationChart.destroy();
  if (statusChart) statusChart.destroy();

  durationChart = new Chart(document.getElementById("durationChart"), {
    type: "line",
    data: {
      labels,
      datasets: [{ label: "Duration Seconds", data: durations, tension: 0.35, borderWidth: 3 }]
    },
    options: { responsive: true, plugins: { legend: { display: true } } }
  });

  statusChart = new Chart(document.getElementById("statusChart"), {
    type: "doughnut",
    data: {
      labels: Object.keys(statusCounts),
      datasets: [{ label: "Run Status", data: Object.values(statusCounts) }]
    },
    options: { responsive: true }
  });
}

refreshDashboard();
setInterval(refreshDashboard, 10000);