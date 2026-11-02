import EventBadge from "./EventBadge";
import { useState } from "react";

function EventTable({ events }) {
  const [selectedEvent, setSelectedEvent] = useState(null);

  return (
    <div style={{ width: "100%", overflowX: "auto" }}>
      <div style={tableContainerStyle}>
        <table style={tableStyle}>
          <thead>
            <tr>
              <th style={thStyle}>Type</th>
              <th style={thStyle}>Time</th>
              <th style={thStyle}>Attacker IP</th>
              <th style={thStyle}>Command</th>
              <th style={thStyle}>Severity</th>
              <th style={thStyle}>Action</th>
            </tr>
          </thead>

          <tbody>
            {events.map((event) => (
              <tr key={event.id} style={trStyle}>
                <td style={tdStyle}>
                  <EventBadge type={event.event_type} />
                </td>

                <td style={{ ...tdStyle, color: "#94A3B8" }}>
                  {new Date(event.timestamp).toLocaleString()}
                </td>

                <td style={tdStyle}>{event.payload?.src_ip || "-"}</td>

                <td style={commandTdStyle} title={event.payload?.input || "-"}>
                  {truncate(event.payload?.input || "-", 80)}
                </td>

                <td style={tdStyle}>
                  <SeverityBadge severity={event.payload?.severity} />
                </td>
                
                <td style={tdStyle}>
                  <button
                    onClick={() => setSelectedEvent(event)}
                    style={viewButtonStyle}
                  >
                    View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selectedEvent && (
        <div style={modalOverlayStyle} onClick={() => setSelectedEvent(null)}>
          <div style={modalStyle} onClick={(e) => e.stopPropagation()}>
            <div style={modalHeaderStyle}>
              <h3 style={modalTitleStyle}>Event Details</h3>
              <button
                onClick={() => setSelectedEvent(null)}
                style={closeButtonStyle}
              >
                ✕
              </button>
            </div>

            <div style={summaryGridStyle}>
              <DetailBox label="Event Type" value={selectedEvent.event_type} />
              <DetailBox label="Attacker IP" value={selectedEvent.payload?.src_ip || "-"} />
              <DetailBox label="Timestamp" value={new Date(selectedEvent.timestamp).toLocaleString()} />
              <DetailBox label="Severity" value={selectedEvent.payload?.severity || "LOW"} />
              <DetailBox label="Threat Score" value={selectedEvent.payload?.threat_score || "1"} />
            </div>

            <div style={{ marginTop: "16px" }}>
              <DetailBox 
                label="Command Executed" 
                value={selectedEvent.payload?.input || "-"} 
                isFullWidth={true}
              />
            </div>

            {selectedEvent.payload?.threat_reasons?.length > 0 && (
              <>
                <h4 style={sectionTitleStyle}>Threat Reasons</h4>
                <ul style={reasonsListStyle}>
                  {selectedEvent.payload.threat_reasons.map((reason, index) => (
                    <li key={index} style={{ marginBottom: "6px" }}>{reason}</li>
                  ))}
                </ul>
              </>
            )}

            {selectedEvent.payload?.virustotal && (
              <>
                <h4 style={sectionTitleStyle}>VirusTotal Intelligence</h4>
                <VirusTotalPanel virustotal={selectedEvent.payload.virustotal} />
              </>
            )}

            <h4 style={sectionTitleStyle}>Raw Payload</h4>
            <pre style={jsonStyle}>
              {JSON.stringify(selectedEvent.payload, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

// --- Premium Minimalist Styles ---

const tableContainerStyle = {
  background: "rgba(255, 255, 255, 0.02)",
  border: "1px solid rgba(255, 255, 255, 0.08)",
  borderRadius: "16px",
  overflow: "hidden",
  backdropFilter: "blur(12px)",
  WebkitBackdropFilter: "blur(12px)",
  marginTop: "16px",
};

const tableStyle = {
  width: "100%",
  tableLayout: "fixed",
  borderCollapse: "collapse",
  fontFamily: "system-ui, -apple-system, sans-serif",
};

const thStyle = {
  padding: "16px",
  textAlign: "left",
  color: "#A1A1AA",
  fontSize: "0.75rem",
  fontWeight: "500",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
  background: "rgba(255, 255, 255, 0.01)",
};

const trStyle = {
  borderBottom: "1px solid rgba(255, 255, 255, 0.03)",
  transition: "background 0.2s ease",
};

const tdStyle = {
  padding: "16px",
  fontSize: "0.875rem",
  color: "#E2E8F0",
  verticalAlign: "middle",
};

const commandTdStyle = {
  ...tdStyle,
  color: "#CBD5E1",
  fontFamily: "monospace",
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};

const viewButtonStyle = {
  background: "rgba(255, 255, 255, 0.05)",
  color: "#F8FAFC",
  border: "1px solid rgba(255, 255, 255, 0.1)",
  borderRadius: "6px",
  padding: "6px 16px",
  fontSize: "0.75rem",
  fontWeight: "500",
  cursor: "pointer",
  transition: "all 0.2s ease",
};

function SeverityBadge({ severity }) {
  let bg = "rgba(34, 197, 94, 0.1)";
  let color = "#4ADE80";
  let border = "rgba(34, 197, 94, 0.2)";

  if (severity === "MEDIUM") {
    bg = "rgba(245, 158, 11, 0.1)";
    color = "#FBBF24";
    border = "rgba(245, 158, 11, 0.2)";
  } else if (severity === "HIGH") {
    bg = "rgba(239, 68, 68, 0.1)";
    color = "#F87171";
    border = "rgba(239, 68, 68, 0.2)";
  }

  return (
    <span style={{
      background: bg,
      color: color,
      border: `1px solid ${border}`,
      padding: "4px 10px",
      borderRadius: "6px",
      fontSize: "0.75rem",
      fontWeight: "500",
      display: "inline-block",
    }}>
      {severity || "LOW"}
    </span>
  );
}

const modalOverlayStyle = {
  position: "fixed",
  inset: 0,
  background: "rgba(0, 0, 0, 0.4)",
  backdropFilter: "blur(8px)",
  WebkitBackdropFilter: "blur(8px)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  zIndex: 1000,
  padding: "2rem",
};

const modalStyle = {
  background: "rgba(15, 23, 42, 0.85)",
  boxShadow: "0 24px 48px rgba(0, 0, 0, 0.4)",
  width: "100%",
  maxWidth: "800px",
  maxHeight: "85vh",
  overflowY: "auto",
  borderRadius: "20px",
  padding: "32px",
  border: "1px solid rgba(255, 255, 255, 0.08)",
  backdropFilter: "blur(24px)",
  WebkitBackdropFilter: "blur(24px)",
  fontFamily: "system-ui, -apple-system, sans-serif",
  color: "#F8FAFC",
};

const modalHeaderStyle = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  marginBottom: "32px",
  paddingBottom: "16px",
  borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
};

const modalTitleStyle = {
  margin: 0,
  fontSize: "1.25rem",
  fontWeight: "500",
  letterSpacing: "-0.01em",
};

const closeButtonStyle = {
  background: "rgba(255, 255, 255, 0.05)",
  color: "#A1A1AA",
  border: "1px solid rgba(255, 255, 255, 0.1)",
  borderRadius: "50%",
  width: "32px",
  height: "32px",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  cursor: "pointer",
  fontSize: "1rem",
  transition: "all 0.2s ease",
};

const sectionTitleStyle = {
  marginTop: "32px",
  marginBottom: "16px",
  fontSize: "0.875rem",
  fontWeight: "600",
  color: "#E2E8F0",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
};

const summaryGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
  gap: "16px",
};

const glassCardStyle = {
  background: "rgba(255, 255, 255, 0.02)",
  border: "1px solid rgba(255, 255, 255, 0.06)",
  borderRadius: "12px",
  padding: "16px",
  display: "flex",
  flexDirection: "column",
  gap: "6px",
};

const labelStyle = {
  fontSize: "0.75rem",
  color: "#94A3B8",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  fontWeight: "500",
};

const valueStyle = {
  fontSize: "1rem",
  color: "#F8FAFC",
  fontWeight: "500",
  wordBreak: "break-word",
};

function DetailBox({ label, value, isFullWidth = false }) {
  return (
    <div style={{ ...glassCardStyle, gridColumn: isFullWidth ? "1 / -1" : "auto" }}>
      <span style={labelStyle}>{label}</span>
      <span style={isFullWidth ? { ...valueStyle, fontFamily: "monospace", fontSize: "0.875rem" } : valueStyle}>
        {value}
      </span>
    </div>
  );
}

const reasonsListStyle = {
  margin: 0,
  padding: "16px 16px 16px 32px",
  background: "rgba(239, 68, 68, 0.05)", // Very subtle red tint
  border: "1px solid rgba(239, 68, 68, 0.15)",
  borderRadius: "12px",
  color: "#FCA5A5",
  fontSize: "0.875rem",
  lineHeight: "1.6",
};

const jsonStyle = {
  background: "rgba(0, 0, 0, 0.3)",
  border: "1px solid rgba(255, 255, 255, 0.05)",
  padding: "16px",
  borderRadius: "12px",
  overflowX: "auto",
  fontSize: "0.8125rem",
  fontFamily: "monospace",
  color: "#94A3B8",
};

// --- VirusTotal Sub-components ---

const vtGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
  gap: "16px",
};

function vtRiskBadgeStyle(malicious) {
  let bg = "rgba(34, 197, 94, 0.1)";
  let color = "#4ADE80";
  let border = "rgba(34, 197, 94, 0.2)";

  if (malicious >= 1) {
    bg = "rgba(245, 158, 11, 0.1)";
    color = "#FBBF24";
    border = "rgba(245, 158, 11, 0.2)";
  }
  if (malicious >= 5) {
    bg = "rgba(239, 68, 68, 0.1)";
    color = "#F87171";
    border = "rgba(239, 68, 68, 0.2)";
  }

  return {
    background: bg,
    color,
    border: `1px solid ${border}`,
    borderRadius: "6px",
    padding: "2px 8px",
    fontSize: "0.6875rem",
    fontWeight: "600",
  };
}

function VirusTotalPanel({ virustotal }) {
  const items = [
    ...(virustotal.domains || []),
    ...(virustotal.urls || []),
    ...(virustotal.hashes || []),
  ];

  if (items.length === 0) return null;

  return (
    <div style={vtGridStyle}>
      {items.map((item, index) => (
        <div key={index} style={glassCardStyle}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
            <span style={labelStyle}>{item.type}</span>
            <span style={vtRiskBadgeStyle(item.malicious || 0)}>
              {item.malicious || 0} malicious
            </span>
          </div>

          <div style={{ color: "#E2E8F0", fontFamily: "monospace", fontSize: "0.8125rem", wordBreak: "break-all", marginBottom: "12px" }}>
            {item.indicator}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px", fontSize: "0.75rem", color: "#64748B" }}>
            <span>Suspicious: {item.suspicious ?? "-"}</span>
            <span>Reputation: {item.reputation ?? "-"}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function truncate(value, maxLength) {
  if (!value) return "-";
  return value.length > maxLength ? value.slice(0, maxLength) + "..." : value;
}

export default EventTable;