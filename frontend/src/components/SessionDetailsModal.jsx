function SessionDetailsModal({ session, events, intelligence, onClose }) {
  if (!session) return null;

  return (
    <div style={overlayStyle} onClick={onClose}>
      <div style={modalStyle} onClick={(e) => e.stopPropagation()}>
        
        <div style={headerStyle}>
          <h3 style={modalTitleStyle}>Session Intelligence</h3>
          <button style={closeButtonStyle} onClick={onClose}>
            ✕
          </button>
        </div>

        <div style={sessionInfoGridStyle}>
          <div style={glassCardStyle}>
            <span style={labelStyle}>Attacker IP</span>
            <span style={valueStyle}>{session.attacker_ip}</span>
          </div>

          <div style={glassCardStyle}>
            <span style={labelStyle}>Threat Score</span>
            <span style={valueStyle}>{session.threat_score}</span>
          </div>

          <div style={glassCardStyle}>
            <span style={labelStyle}>AbuseIPDB</span>
            <span style={valueStyle}>
              {session.abuseipdb?.abuse_confidence_score ?? "-"} / 100
            </span>
          </div>

          <div style={glassCardStyle}>
            <span style={labelStyle}>ISP</span>
            <span style={valueStyle}>{session.abuseipdb?.isp || "-"}</span>
          </div>

          <div style={glassCardStyle}>
            <span style={labelStyle}>Usage Type</span>
            <span style={valueStyle}>{session.abuseipdb?.usage_type || "-"}</span>
          </div>
        </div>

        <div style={aiSummaryBoxStyle}>
          <span style={labelStyle}>Analyst Summary</span>
          <p style={aiSummaryTextStyle}>{session.ai_summary || "-"}</p>
        </div>

        {intelligence?.correlation && (
          <>
            <h4 style={sectionTitleStyle}>Correlation Summary</h4>
            <div style={gridStyle}>
              <div style={glassCardStyle}>
                <span style={labelStyle}>Session Risk</span>
                <span style={riskBadgeStyle(intelligence.correlation.session_risk)}>
                  {intelligence.correlation.session_risk}
                </span>
              </div>

              <div style={glassCardStyle}>
                <span style={labelStyle}>Risk Score</span>
                <span style={valueStyle}>{intelligence.correlation.session_risk_score}/10</span>
              </div>

              <div style={glassCardStyle}>
                <span style={labelStyle}>IOC Count</span>
                <span style={valueStyle}>{intelligence.correlation.ioc_count}</span>
              </div>

              <div style={glassCardStyle}>
                <span style={labelStyle}>ATT&CK Chain Length</span>
                <span style={valueStyle}>{intelligence.correlation.attack_chain_length}</span>
              </div>
            </div>
          </>
        )}

        {intelligence?.behavior_analysis && (
          <div style={behaviorContainerStyle}>
            <h3 style={{ margin: "0 0 8px 0", fontSize: "1rem", color: "#F8FAFC" }}>
              Behavioral Analysis
            </h3>
            <p style={{ color: "#CBD5E1", fontSize: "0.875rem", lineHeight: "1.6", margin: "0 0 12px 0" }}>
              {intelligence.behavior_analysis.summary}
            </p>
            <p style={{ color: "#94A3B8", fontSize: "0.8125rem", margin: "0 0 16px 0" }}>
              Severity: {intelligence.behavior_analysis.overall_behavior_severity}
            </p>

            {intelligence.behavior_analysis.attack_timeline?.length > 0 && (
              <>
                <h4 style={subsectionTitleStyle}>Behavior Timeline</h4>
                <div style={tagContainerStyle}>
                  {intelligence.behavior_analysis.attack_timeline.map((stage, index) => (
                    <span key={index} style={tagBadgeStyle}>{stage}</span>
                  ))}
                </div>
              </>
            )}

            {intelligence.behavior_analysis.behaviors?.map((behavior, index) => (
              <div key={index} style={innerGlassCardStyle}>
                <strong style={behaviorTitleStyle}>{behavior.behavior_name}</strong>
                <p style={behaviorDescStyle}>{behavior.description}</p>
                <div style={metaFlexStyle}>
                  <span style={metaTextStyle}>Confidence: {Math.round(behavior.confidence * 100)}%</span>
                  <span style={metaTextStyle}>MITRE: {behavior.mitre_techniques?.join(", ")}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {intelligence && (
          <>
            <h4 style={sectionTitleStyle}>Aggregated IOCs</h4>
            <div style={gridStyle}>
              <IocBox label="URLs" values={intelligence.iocs?.urls} />
              <IocBox label="Domains" values={intelligence.iocs?.domains} />
              <IocBox label="Hashes" values={intelligence.iocs?.hashes} />
              <IocBox label="IPs" values={intelligence.iocs?.ips} />
            </div>

            {intelligence.virustotal?.length > 0 && (
              <>
                <h4 style={sectionTitleStyle}>VirusTotal Intelligence</h4>
                <div style={gridStyle}>
                  {intelligence.virustotal.map((item, index) => (
                    <div key={index} style={glassCardStyle}>
                      <span style={labelStyle}>{item.type?.toUpperCase()}</span>
                      <div style={indicatorStyle}>{item.indicator}</div>
                      <div style={metaGridStyle}>
                        <span>Malicious: {item.malicious ?? "-"}</span>
                        <span>Suspicious: {item.suspicious ?? "-"}</span>
                        <span>Reputation: {item.reputation ?? "-"}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </>
        )}

        {intelligence?.correlation?.top_iocs?.length > 0 && (
          <>
            <h4 style={sectionTitleStyle}>Top Risk Indicators</h4>
            <div style={gridStyle}>
              {intelligence.correlation.top_iocs.map((item, index) => (
                <div key={index} style={glassCardStyle}>
                  <span style={labelStyle}>{item.type?.toUpperCase()}</span>
                  <div style={indicatorStyle}>{item.indicator}</div>
                  <div style={metaGridStyle}>
                    <span>Score: {item.ioc_score}/10</span>
                    <span>Severity: {item.ioc_severity}</span>
                    <span>Malicious: {item.malicious ?? "-"}</span>
                  </div>
                  {item.ioc_reasons?.length > 0 && (
                    <ul style={reasonListStyle}>
                      {item.ioc_reasons.map((reason, idx) => (
                        <li key={idx}>{reason}</li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          </>
        )}

        {session.attack_chain?.length > 0 && (
          <>
            <h4 style={sectionTitleStyle}>ATT&CK Chain</h4>
            <div style={tagContainerStyle}>
              {session.attack_chain.map((tactic, index) => (
                <span key={index} style={tagBadgeStyle}>{tactic}</span>
              ))}
            </div>
          </>
        )}

        {session.mitre_techniques?.length > 0 && (
          <>
            <h4 style={sectionTitleStyle}>MITRE ATT&CK Techniques</h4>
            <div style={gridStyle}>
              {session.mitre_techniques.map((technique) => (
                <a
                  key={technique.id}
                  href={technique.url}
                  target="_blank"
                  rel="noreferrer"
                  style={{ ...glassCardStyle, textDecoration: "none" }}
                >
                  <span style={labelStyle}>{technique.id}</span>
                  <span style={linkValueStyle}>{technique.name}</span>
                </a>
              ))}
            </div>
          </>
        )}

        <h4 style={sectionTitleStyle}>Event Timeline</h4>
        <div style={timelineContainerStyle}>
          {events.map((event) => (
            <div key={event.id} style={timelineItemStyle}>
              <div style={timelineDotStyle} />
              <div style={timeStyle}>
                {new Date(event.timestamp).toLocaleString()}
              </div>
              <div style={eventTypeStyle}>{event.event_type}</div>
              <div style={commandStyle}>
                {event.payload?.input || event.payload?.message || "-"}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// --- Premium Minimalist Styles ---

const overlayStyle = {
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
  background: "rgba(15, 23, 42, 0.85)", // Deep slate core
  boxShadow: "0 24px 48px rgba(0, 0, 0, 0.4)",
  width: "100%",
  maxWidth: "960px",
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

const headerStyle = {
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

const subsectionTitleStyle = {
  ...sectionTitleStyle,
  marginTop: "16px",
  fontSize: "0.75rem",
  color: "#94A3B8",
};

const gridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
  gap: "16px",
};

const sessionInfoGridStyle = {
  ...gridStyle,
  marginBottom: "24px",
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

const innerGlassCardStyle = {
  ...glassCardStyle,
  background: "rgba(0, 0, 0, 0.2)",
  marginTop: "12px",
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

const linkValueStyle = {
  ...valueStyle,
  color: "#60A5FA",
  transition: "color 0.2s ease",
};

const aiSummaryBoxStyle = {
  background: "linear-gradient(145deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.01) 100%)",
  border: "1px solid rgba(255, 255, 255, 0.08)",
  borderRadius: "16px",
  padding: "24px",
  marginTop: "24px",
};

const aiSummaryTextStyle = {
  marginTop: "12px",
  marginBottom: 0,
  fontSize: "0.9375rem",
  lineHeight: "1.6",
  color: "#E2E8F0",
};

const behaviorContainerStyle = {
  background: "rgba(15, 23, 42, 0.4)",
  border: "1px solid rgba(56, 189, 248, 0.15)", // Subtle blue tint for analysis focus
  borderRadius: "16px",
  padding: "24px",
  marginTop: "32px",
};

const behaviorTitleStyle = {
  color: "#F87171",
  fontSize: "0.875rem",
  fontWeight: "500",
};

const behaviorDescStyle = {
  color: "#CBD5E1",
  fontSize: "0.875rem",
  lineHeight: "1.5",
  margin: "6px 0",
};

const metaFlexStyle = {
  display: "flex",
  gap: "16px",
  marginTop: "8px",
};

const metaTextStyle = {
  color: "#64748B",
  fontSize: "0.75rem",
};

const metaGridStyle = {
  display: "grid",
  gridTemplateColumns: "1fr 1fr",
  gap: "4px",
  fontSize: "0.75rem",
  color: "#94A3B8",
  marginTop: "8px",
};

const tagContainerStyle = {
  display: "flex",
  flexWrap: "wrap",
  gap: "8px",
};

const tagBadgeStyle = {
  background: "rgba(99, 102, 241, 0.1)",
  color: "#818CF8",
  border: "1px solid rgba(99, 102, 241, 0.2)",
  padding: "4px 12px",
  borderRadius: "8px",
  fontSize: "0.75rem",
  fontWeight: "500",
};

const indicatorStyle = {
  color: "#E2E8F0",
  fontSize: "0.875rem",
  fontFamily: "monospace",
  wordBreak: "break-all",
  background: "rgba(0,0,0,0.2)",
  padding: "6px 8px",
  borderRadius: "6px",
  marginTop: "4px",
};

const reasonListStyle = {
  margin: "8px 0 0 0",
  paddingLeft: "16px",
  color: "#94A3B8",
  fontSize: "0.75rem",
};

const timelineContainerStyle = {
  position: "relative",
  paddingLeft: "24px",
  marginTop: "16px",
};

const timelineItemStyle = {
  position: "relative",
  paddingBottom: "24px",
  borderLeft: "1px solid rgba(255, 255, 255, 0.1)",
  paddingLeft: "24px",
  marginLeft: "-24px",
};

const timelineDotStyle = {
  position: "absolute",
  left: "-5px",
  top: "4px",
  width: "9px",
  height: "9px",
  borderRadius: "50%",
  background: "#38BDF8",
  boxShadow: "0 0 0 4px rgba(15, 23, 42, 0.85)",
};

const timeStyle = {
  color: "#64748B",
  fontSize: "0.75rem",
  marginBottom: "4px",
};

const eventTypeStyle = {
  color: "#F8FAFC",
  fontSize: "0.875rem",
  fontWeight: "500",
};

const commandStyle = {
  color: "#94A3B8",
  fontSize: "0.8125rem",
  fontFamily: "monospace",
  marginTop: "6px",
  background: "rgba(255,255,255,0.02)",
  padding: "8px",
  borderRadius: "6px",
  wordBreak: "break-all",
};

function riskBadgeStyle(risk) {
  let bg = "rgba(34, 197, 94, 0.1)";
  let color = "#4ADE80";
  let border = "rgba(34, 197, 94, 0.2)";

  if (risk === "MEDIUM") {
    bg = "rgba(245, 158, 11, 0.1)";
    color = "#FBBF24";
    border = "rgba(245, 158, 11, 0.2)";
  } else if (risk === "HIGH") {
    bg = "rgba(239, 68, 68, 0.1)";
    color = "#F87171";
    border = "rgba(239, 68, 68, 0.2)";
  }

  return {
    background: bg,
    color,
    border: `1px solid ${border}`,
    padding: "4px 10px",
    borderRadius: "6px",
    fontSize: "0.75rem",
    fontWeight: "500",
    display: "inline-block",
    marginTop: "4px",
  };
}

function IocBox({ label, values }) {
  return (
    <div style={glassCardStyle}>
      <span style={labelStyle}>{label}</span>
      {values && values.length > 0 ? (
        values.map((value, index) => (
          <div key={index} style={{ ...indicatorStyle, marginTop: index === 0 ? "8px" : "4px" }}>
            {value}
          </div>
        ))
      ) : (
        <span style={{ color: "#64748B", fontSize: "0.875rem", marginTop: "8px" }}>None</span>
      )}
    </div>
  );
}

export default SessionDetailsModal;