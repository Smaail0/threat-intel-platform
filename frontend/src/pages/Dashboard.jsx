import { useEffect, useState } from "react";
import api from "../api/client";

import OverviewCards from "../components/OverviewCards";
import EventTable from "../components/EventTable";
import ChartsPanel from "../components/ChartsPanel";
import HighRiskSessions from "../components/HighRiskSessions";
import SessionDetailsModal from "../components/SessionDetailsModal";
import AttackMap from "../components/AttackMap";
import BehaviorStatsPanel from "../components/BehaviorStatsPanel";

function Dashboard() {
  // ... (Keep all your existing state and useEffect logic exactly the same) ...
  const [overview, setOverview] = useState(null);
  const [events, setEvents] = useState([]);
  const [commands, setCommands] = useState([]);
  const [logins, setLogins] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [topIps, setTopIps] = useState([]);
  const [highRiskSessions, setHighRiskSessions] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionEvents, setSessionEvents] = useState([]);
  const [countries, setCountries] = useState([]);
  const [asns, setAsns] = useState([]);
  const [attackLocations, setAttackLocations] = useState([]);
  const [sessionIntelligence, setSessionIntelligence] = useState(null);
  const [topBehaviors, setTopBehaviors] = useState([]);
  const [behaviorStages, setBehaviorStages] = useState([]);
  const [highSeverityBehaviors, setHighSeverityBehaviors] = useState(null);
  const [behaviorSessions, setBehaviorSessions] = useState([]);
  const [selectedBehavior, setSelectedBehavior] = useState(null);

  async function handleSelectBehavior(behaviorName) {
    setSelectedBehavior(behaviorName);
    const res = await api.get(`/behaviors/${encodeURIComponent(behaviorName)}/sessions`);
    setBehaviorSessions(res.data);
  }

  async function handleSelectStage(stage) {
    setSelectedBehavior(stage);
    const res = await api.get(`/behavior-stages/${encodeURIComponent(stage)}/sessions`);
    setBehaviorSessions(res.data);
  }

  async function handleSelectSession(session) {
    setSelectedSession(session);
    const eventsRes = await api.get(`/sessions/${session.id}/events`);
    const intelRes = await api.get(`/sessions/${session.id}/intelligence`);
    setSessionEvents(eventsRes.data);
    setSessionIntelligence(intelRes.data);
  }

  useEffect(() => {
    async function fetchData() {
      try {
        const overviewRes = await api.get("/stats/overview");
        const eventsRes = await api.get("/events");
        const commandsRes = await api.get("/stats/commands");
        const loginsRes = await api.get("/stats/logins");
        const timelineRes = await api.get("/stats/timeline");
        const topIpsRes = await api.get("/stats/top_ips");
        const highRiskRes = await api.get("/sessions/high-risk");
        const countriesRes = await api.get("/stats/countries");
        const asnsRes = await api.get("/stats/asns");
        const mapRes = await api.get("/map/attack-locations");
        const behaviorsRes = await api.get("/stats/behaviors");
        const stagesRes = await api.get("/stats/behavior-stages");
        const highSeverityRes = await api.get("/stats/high-severity-behaviors");

        setTopBehaviors(behaviorsRes.data);
        setBehaviorStages(stagesRes.data);
        setHighSeverityBehaviors(highSeverityRes.data.high_severity_behaviors);
        setAttackLocations(mapRes.data);
        setCountries(countriesRes.data);
        setAsns(asnsRes.data);
        setHighRiskSessions(highRiskRes.data);
        setTopIps(topIpsRes.data);
        setCommands(commandsRes.data);
        setLogins(loginsRes.data);
        setTimeline(timelineRes.data);
        setOverview(overviewRes.data);
        setEvents(eventsRes.data);
      } catch (err) {
        console.error(err);
      }
    }
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={appWrapperStyle}>
      <div style={appContainerStyle}>
        <header style={headerStyle}>
          <h1 style={titleStyle}>Threat Intelligence</h1>
          <div style={liveIndicatorStyle}>
            <div style={pulseDotStyle} />
            System Live
          </div>
        </header>

        <OverviewCards overview={overview} />

        {/* TIER 1: Bento Box Split (65% Map / 35% Behaviors) */}
        <div style={bentoRowStyle}>
          <div style={mapColumnStyle}>
            <AttackMap locations={attackLocations} />
          </div>
          
          <div style={behaviorColumnStyle}>
            <BehaviorStatsPanel
              topBehaviors={topBehaviors}
              behaviorStages={behaviorStages}
              highSeverityBehaviors={highSeverityBehaviors}
              onSelectBehavior={handleSelectBehavior}
              onSelectStage={handleSelectStage}
            />

            {selectedBehavior && (
              <div style={behaviorSessionsPanelStyle}>
                <h3 style={sectionTitleStyle}>
                  Sessions with: <span style={{ color: "#F8FAFC" }}>{selectedBehavior}</span>
                </h3>

                <div style={{ marginTop: "16px" }}>
                  {behaviorSessions.length === 0 ? (
                    <p style={{ color: "#94A3B8", fontSize: "0.875rem" }}>No sessions found.</p>
                  ) : (
                    behaviorSessions.map((item) => (
                      <button
                        key={item.session_id}
                        type="button"
                        onMouseEnter={(e) => {
                          e.currentTarget.style.background = "rgba(255, 255, 255, 0.06)";
                          e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.15)";
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background = "rgba(255, 255, 255, 0.02)";
                          e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.05)";
                        }}
                        style={behaviorSessionButtonStyle}
                        onClick={() =>
                          handleSelectSession({
                            id: item.session_id,
                            attacker_ip: item.attacker_ip,
                            threat_score: item.threat_score,
                          })
                        }
                      >
                        <div>
                          <strong style={{ display: "block", color: "#F8FAFC", marginBottom: "4px" }}>
                            {item.attacker_ip}
                          </strong>
                          <div style={{ color: "#64748B", fontSize: "0.75rem" }}>
                            {new Date(item.timestamp).toLocaleString()}
                          </div>
                        </div>
                        <div style={{ color: "#94A3B8" }}>
                          Score: <strong style={{ color: "#F87171" }}>{item.threat_score}</strong>
                        </div>
                        <div style={{ textAlign: "right" }}>
                          <span style={stageBadgeStyle}>{item.behavior.stage}</span>
                        </div>
                      </button>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* TIER 3: Telemetry Grid */}
        <div style={fullWidthSectionStyle}>
          <h2 style={sectionTitleStyle}>Telemetry & Metrics</h2>
          <ChartsPanel
            commands={commands}
            logins={logins}
            timeline={timeline}
            topIps={topIps}
            countries={countries}
            asns={asns}
          />
        </div>

        {/* TIER 2: Tabular Data */}
        <div style={fullWidthSectionStyle}>
          <HighRiskSessions
            sessions={highRiskSessions}
            onSelectSession={handleSelectSession}
          />
        </div>

        <div style={fullWidthSectionStyle}>
          <div style={eventWrapperStyle}>
            <h2 style={sectionTitleStyle}>Recent Events</h2>
            <EventTable events={events} />
          </div>
        </div>

        <SessionDetailsModal
          session={selectedSession}
          events={sessionEvents}
          intelligence={sessionIntelligence}
          onClose={() => {
            setSelectedSession(null);
            setSessionEvents([]);
            setSessionIntelligence(null);
          }}
        />
      </div>
    </div>
  );
}

// --- Premium Architectural Layout Styles ---

const appWrapperStyle = {
  background: "radial-gradient(ellipse at top center, #0F172A 0%, #020617 100%)",
  minHeight: "100vh",
  width: "100%",
  color: "#F8FAFC",
  fontFamily: "system-ui, -apple-system, sans-serif",
  padding: "32px 24px", 
};

// The invisible anchor: keeps the dashboard huge but perfectly proportioned.
const appContainerStyle = {
  maxWidth: "1600px", 
  margin: "0 auto",
  width: "100%",
};

const headerStyle = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  marginBottom: "32px",
  paddingBottom: "24px",
  borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
};

const titleStyle = {
  margin: 0,
  fontSize: "1.5rem",
  fontWeight: "500",
  letterSpacing: "-0.02em",
};

const liveIndicatorStyle = {
  display: "flex",
  alignItems: "center",
  gap: "8px",
  fontSize: "0.75rem",
  color: "#4ADE80",
  fontWeight: "600",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  background: "rgba(34, 197, 94, 0.1)",
  padding: "6px 16px",
  borderRadius: "999px",
  border: "1px solid rgba(34, 197, 94, 0.2)",
};

const pulseDotStyle = {
  width: "8px",
  height: "8px",
  borderRadius: "50%",
  background: "#4ADE80",
  boxShadow: "0 0 10px rgba(74, 222, 128, 0.6)",
};

// --- Flex Box Bento Layout ---

const bentoRowStyle = {
  display: "flex",
  flexWrap: "wrap",
  gap: "32px",
  marginBottom: "32px",
  alignItems: "stretch",
};

const mapColumnStyle = {
  flex: "2 1 800px", // Takes ~65% of the width
  display: "flex",
  flexDirection: "column",
};

const behaviorColumnStyle = {
  flex: "1 1 400px", // Takes ~35% of the width
  display: "flex",
  flexDirection: "column",
  gap: "32px",
};

const fullWidthSectionStyle = {
  width: "100%",
  marginBottom: "32px",
};

const sectionTitleStyle = {
  margin: "0 0 16px 0",
  fontSize: "1.125rem",
  fontWeight: "500",
  color: "#E2E8F0",
  letterSpacing: "-0.01em",
};

const eventWrapperStyle = {
  background: "rgba(255, 255, 255, 0.01)",
  border: "1px solid rgba(255, 255, 255, 0.05)",
  borderRadius: "16px",
  padding: "24px",
};

const behaviorSessionsPanelStyle = {
  background: "rgba(15, 23, 42, 0.4)",
  border: "1px solid rgba(56, 189, 248, 0.15)",
  borderRadius: "16px",
  padding: "24px",
};

const behaviorSessionButtonStyle = {
  width: "100%",
  display: "grid",
  gridTemplateColumns: "1.5fr 1fr 1fr",
  gap: "16px",
  alignItems: "center",
  padding: "16px",
  background: "rgba(255, 255, 255, 0.02)",
  color: "#F8FAFC",
  border: "1px solid rgba(255, 255, 255, 0.05)",
  borderRadius: "12px",
  cursor: "pointer",
  marginBottom: "8px",
  textAlign: "left",
  transition: "all 0.2s ease",
  fontSize: "0.875rem",
};

const stageBadgeStyle = {
  background: "rgba(192, 132, 252, 0.1)",
  color: "#C084FC",
  border: "1px solid rgba(192, 132, 252, 0.2)",
  padding: "4px 10px",
  borderRadius: "8px",
  fontSize: "0.75rem",
  fontWeight: "500",
};

export default Dashboard;