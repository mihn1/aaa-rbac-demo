(function () {
  async function fetchJSON(url, options) {
    const response = await fetch(url, Object.assign({ headers: { 'Accept': 'application/json' } }, options));
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  async function refreshEvents() {
    try {
      const events = await fetchJSON('/logs/events');
      const tbody = document.getElementById('event-table');
      if (!tbody) return;

      if (!Array.isArray(events) || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-slate-400 py-4">No events captured yet.</td></tr>';
        return;
      }

      const rows = events
        .map((event) => {
          const occurred = new Date(event.occurred_at);
          const when = occurred.toLocaleString();
          const latency = event.latency_ms != null ? `${event.latency_ms} ms` : '-';
          return `
            <tr class="hover:bg-slate-900/60">
              <td class="px-3 py-2 whitespace-nowrap">${when}</td>
              <td class="px-3 py-2">${event.user_name ?? '-'}</td>
              <td class="px-3 py-2">${event.role_name ?? '-'}</td>
              <td class="px-3 py-2 uppercase">${event.action ?? '-'}</td>
              <td class="px-3 py-2">${event.endpoint ?? '-'}</td>
              <td class="px-3 py-2">${event.status_code ?? '-'}</td>
              <td class="px-3 py-2">${latency}</td>
            </tr>
          `;
        })
        .join('');
      tbody.innerHTML = rows;
    } catch (err) {
      console.error(err);
    }
  }

  async function acknowledgeAlert(alertId) {
    try {
      await fetchJSON(`/logs/alerts/${alertId}/ack`, { method: 'POST' });
      const alertEl = document.querySelector(`[data-alert-id="${alertId}"]`);
      if (alertEl) {
        alertEl.querySelectorAll('button[data-ack-button]').forEach((btn) => btn.remove());
        const badge = document.createElement('span');
        badge.className = 'text-xs text-emerald-400';
        badge.textContent = 'Acknowledged';
        alertEl.appendChild(badge);
      }
    } catch (err) {
      console.error('Failed to acknowledge alert', err);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const refreshBtn = document.getElementById('refresh-events');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', refreshEvents);
    }

    document.querySelectorAll('button[data-ack-button]').forEach((btn) => {
      btn.addEventListener('click', () => acknowledgeAlert(btn.dataset.ackButton));
    });

    refreshEvents();
    window.setInterval(refreshEvents, 15000);
  });
})();
