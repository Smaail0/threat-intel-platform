function HighRiskSessions({ sessions, onSelectSession }) {
  if (!sessions || sessions.length === 0) {
    return (
      <div style={cardStyle}>
        <h3 style={titleStyle}>High-Risk Sessions</h3>
        <p style={{ color: "#A1A1AA", fontSize: "0.875rem" }}>
          No high-risk sessions detected.
        </p>
      </div>
    );
  }

  return (
    <div style={cardStyle}>
      <h3 style={titleStyle}>High-Risk Sessions</h3>

      <div style={{ overflowX: "auto" }}>
        <table style={tableStyle}>
          <thead>
            <tr>
              <th style={thStyle}>Attacker IP</th>
              <th style={thStyle}>Service</th>
              <th style={thStyle}>Threat Score</th>
              <th style={thStyle}>Abuse Score</th>
              <th style={thStyle}>AI Summary</th>
              <th style={thStyle}>Time</th>
              <th style={thStyle}>Action</th>
            </tr>
          </thead>

          <tbody>
            {sessions.map((session) => (
              <tr key={session.id}>
                <td style={tdStyle}>{session.attacker_ip}</td>
                <td style={tdStyle}>{session.service}</td>

                <td style={tdStyle}>
                  <span style={scoreBadgeStyle(session.threat_score)}>
                    {session.threat_score}
                  </span>
                </td>

                <td style={tdStyle}>
                  {session.abuseipdb?.abuse_confidence_score ?? "-"}
                </td>

                <td style={summaryTdStyle}>{session.ai_summary || "-"}</td>

                <td style={{ ...tdStyle, color: "#A1A1AA" }}>
                  {new Date(session.timestamp).toLocaleString()}
                </td>

                <td style={tdStyle}>
                  <button
                    style={viewButtonStyle}
                    onClick={() => onSelectSession(session)}
                  >
                    View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- Premium Inline Styles ---

const cardStyle = {
  background: "rgba(255, 255, 255, 0.02)",
  border: "1px solid rgba(255, 255, 255, 0.08)",
  borderRadius: "16px",
  padding: "24px",
  marginBottom: "32px",
  backdropFilter: "blur(12px)",
  WebkitBackdropFilter: "blur(12px)",
  fontFamily: "system-ui, -apple-system, sans-serif",
};

const titleStyle = {
  margin: "0 0 24px 0",
  fontSize: "1.125rem",
  fontWeight: "500",
  color: "#F8FAFC",
  letterSpacing: "-0.01em",
};

const tableStyle = {
  width: "100%",
  borderCollapse: "collapse",
  textAlign: "left",
};

const thStyle = {
  color: "#A1A1AA",
  padding: "0 16px 16px 16px",
  fontSize: "0.75rem",
  fontWeight: "500",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
};

const tdStyle = {
  color: "#E2E8F0",
  padding: "16px",
  fontSize: "0.875rem",
  borderBottom: "1px solid rgba(255, 255, 255, 0.03)",
  verticalAlign: "middle",
};

// Generous width for the Gemma 4 summary to ensure it reads well
const summaryTdStyle = {
  ...tdStyle,
  maxWidth: "380px",
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
  color: "#CBD5E1",
};

// Ghost button styling instead of heavy solid colors
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

// Translucent contextual badges
function scoreBadgeStyle(score) {
  let bg = "rgba(34, 197, 94, 0.1)";
  let color = "#4ADE80";
  let border = "rgba(34, 197, 94, 0.2)"; // Low Risk / Green

  if (score >= 7) {
    bg = "rgba(239, 68, 68, 0.1)";
    color = "#F87171";
    border = "rgba(239, 68, 68, 0.2)"; // High Risk / Red
  } else if (score >= 4) {
    bg = "rgba(245, 158, 11, 0.1)";
    color = "#FBBF24";
    border = "rgba(245, 158, 11, 0.2)"; // Medium Risk / Orange
  }

  return {
    background: bg,
    color: color,
    border: `1px solid ${border}`,
    padding: "4px 10px",
    borderRadius: "6px",
    fontSize: "0.75rem",
    fontWeight: "500",
    display: "inline-block",
    textAlign: "center",
    minWidth: "24px",
  };
}

export default HighRiskSessions;