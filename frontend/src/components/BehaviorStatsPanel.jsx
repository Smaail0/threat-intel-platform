import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { useState } from "react";

function BehaviorStatsPanel({
  topBehaviors,
  behaviorStages,
  highSeverityBehaviors,
  onSelectBehavior,
  onSelectStage,
}) {
  const COLORS = [
    "rgba(248, 113, 113, 0.8)", // red
    "rgba(251, 146, 60, 0.8)",  // orange
    "rgba(250, 204, 21, 0.8)",  // yellow
    "rgba(74, 222, 128, 0.8)",  // green
    "rgba(56, 189, 248, 0.8)",  // blue
    "rgba(192, 132, 252, 0.8)", // purple
  ];

  return (
    <div style={{ marginTop: "32px", marginBottom: "32px" }}>
      <h2 style={sectionTitleStyle}>Behavior Intelligence</h2>

      <div style={gridStyle}>
        <div style={kpiCardStyle}>
          <h3 style={cardTitleStyle}>High-Severity Behaviors</h3>
          <div style={kpiValueStyle}>{highSeverityBehaviors ?? 0}</div>
          <div style={subtleTextStyle}>Detected high-risk attacker behaviors</div>
        </div>

        <div style={glassCardStyle}>
          <h3 style={cardTitleStyle}>Top Behaviors</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={topBehaviors} margin={{ left: -20, bottom: 0 }}>
              <XAxis dataKey="behavior" hide />
              <YAxis stroke="#94A3B8" fontSize={12} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "#F8FAFC" }} cursor={{ fill: "rgba(255,255,255,0.02)" }} />
              <Bar dataKey="count" fill="rgba(248, 113, 113, 0.8)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>

          <div style={{ marginTop: "24px", display: "flex", flexDirection: "column", gap: "8px" }}>
            {topBehaviors.map((item) => (
              <InteractiveRow 
                key={item.behavior} 
                label={item.behavior} 
                count={item.count} 
                onClick={() => onSelectBehavior(item.behavior)} 
              />
            ))}
          </div>
        </div>

        <div style={glassCardStyle}>
          <h3 style={cardTitleStyle}>Behavior Stages</h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={behaviorStages}
                dataKey="count"
                nameKey="stage"
                outerRadius={80}
                innerRadius={60}
                paddingAngle={5}
                stroke="none"
              >
                {behaviorStages.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "#F8FAFC" }} />
            </PieChart>
          </ResponsiveContainer>

          <div style={{ marginTop: "24px", display: "flex", flexDirection: "column", gap: "8px" }}>
            {behaviorStages.map((item) => (
              <InteractiveRow 
                key={item.stage} 
                label={item.stage} 
                count={item.count} 
                onClick={() => onSelectStage(item.stage)} 
                isSuccess={true}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// --- Interactive Row Component for clean hover states ---
function InteractiveRow({ label, count, onClick, isSuccess = false }) {
  const [isHovered, setIsHovered] = useState(false);
  
  const hoverColor = isSuccess ? "rgba(74, 222, 128, 0.1)" : "rgba(56, 189, 248, 0.1)";
  const borderColor = isSuccess ? "rgba(74, 222, 128, 0.2)" : "rgba(56, 189, 248, 0.2)";

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      style={{
        width: "100%",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        background: isHovered ? hoverColor : "rgba(255, 255, 255, 0.02)",
        border: `1px solid ${isHovered ? borderColor : "rgba(255, 255, 255, 0.05)"}`,
        borderRadius: "8px",
        padding: "12px 16px",
        color: "#F8FAFC",
        fontSize: "0.8125rem",
        cursor: "pointer",
        transition: "all 0.2s ease",
        fontFamily: "system-ui, -apple-system, sans-serif",
      }}
    >
      <span style={{ fontWeight: "500", textalign: "left" }}>{label}</span>
      <span style={{ display: "flex", alignItems: "center", gap: "12px", color: "#94A3B8" }}>
        <strong>{count}</strong>
        <span style={{ fontSize: "1rem", color: isHovered ? "#F8FAFC" : "#64748B", transition: "color 0.2s ease" }}>→</span>
      </span>
    </button>
  );
}

// --- Styles ---

const sectionTitleStyle = {
  marginBottom: "24px",
  fontSize: "1.125rem",
  fontWeight: "500",
  color: "#F8FAFC",
  letterSpacing: "-0.01em",
  fontFamily: "system-ui, -apple-system, sans-serif",
};

const gridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))",
  gap: "24px",
};

const glassCardStyle = {
  background: "rgba(255, 255, 255, 0.02)",
  border: "1px solid rgba(255, 255, 255, 0.08)",
  borderRadius: "16px",
  padding: "24px",
  backdropFilter: "blur(12px)",
  WebkitBackdropFilter: "blur(12px)",
  fontFamily: "system-ui, -apple-system, sans-serif",
  display: "flex",
  flexDirection: "column",
};

const kpiCardStyle = {
  ...glassCardStyle,
  justifyContent: "center",
  alignItems: "center",
  textAlign: "center",
  background: "linear-gradient(145deg, rgba(239, 68, 68, 0.05) 0%, rgba(255,255,255,0.01) 100%)", // Subtle red tint for danger
};

const cardTitleStyle = {
  margin: "0 0 16px 0",
  fontSize: "0.875rem",
  fontWeight: "500",
  color: "#A1A1AA",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  alignSelf: "flex-start",
};

const kpiValueStyle = {
  fontSize: "4rem",
  fontWeight: "600",
  color: "#F87171", // Soft red
  letterSpacing: "-0.02em",
  margin: "16px 0",
};

const subtleTextStyle = {
  color: "#94A3B8",
  fontSize: "0.875rem",
};

const tooltipStyle = {
  backgroundColor: "rgba(15, 23, 42, 0.9)",
  border: "1px solid rgba(255, 255, 255, 0.1)",
  borderRadius: "8px",
  backdropFilter: "blur(8px)",
  color: "#F8FAFC",
  fontSize: "0.8125rem",
  boxShadow: "0 10px 25px rgba(0,0,0,0.5)",
};

export default BehaviorStatsPanel;