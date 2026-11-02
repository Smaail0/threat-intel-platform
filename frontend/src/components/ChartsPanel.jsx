import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  CartesianGrid
} from "recharts";

function ChartsPanel({ commands, logins, timeline, topIps, countries, asns }) {
  // Translucent, premium color palette for charts
  const colors = {
    red: "rgba(248, 113, 113, 0.8)",
    green: "rgba(74, 222, 128, 0.8)",
    purple: "rgba(192, 132, 252, 0.8)",
    orange: "rgba(251, 146, 60, 0.8)",
    blue: "rgba(56, 189, 248, 0.8)",
    grid: "rgba(255, 255, 255, 0.05)",
    text: "#94A3B8"
  };

  return (
    <div style={panelGridStyle}>
      <ChartCard title="Top Attacker IPs">
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={topIps} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
            <XAxis dataKey="ip" stroke={colors.text} fontSize={12} tickLine={false} axisLine={false} />
            <YAxis stroke={colors.text} fontSize={12} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "#F8FAFC" }} />
            <Bar dataKey="count" fill={colors.red} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Top Countries">
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={countries} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
            <XAxis dataKey="country_iso" stroke={colors.text} fontSize={12} tickLine={false} axisLine={false} />
            <YAxis stroke={colors.text} fontSize={12} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "#F8FAFC" }} />
            <Bar dataKey="count" fill={colors.green} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Top ASN Organizations">
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={asns} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
            <XAxis dataKey="organization" stroke={colors.text} fontSize={12} tickLine={false} axisLine={false} tick={false} />
            <YAxis stroke={colors.text} fontSize={12} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "#F8FAFC" }} />
            <Bar dataKey="count" fill={colors.purple} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Top Commands">
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={commands} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
            <XAxis dataKey="command" stroke={colors.text} fontSize={12} tickLine={false} axisLine={false} />
            <YAxis stroke={colors.text} fontSize={12} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "#F8FAFC" }} />
            <Bar dataKey="count" fill={colors.orange} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Login Results">
        <ResponsiveContainer width="100%" height={250}>
          <PieChart>
            <Pie
              data={logins}
              dataKey="count"
              nameKey="event_type"
              outerRadius={80}
              innerRadius={60} // Turned into a sleek donut chart
              paddingAngle={5}
              stroke="none"
            >
              {logins.map((_, index) => (
                <Cell key={index} fill={index === 0 ? colors.green : colors.red} />
              ))}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "#F8FAFC" }} />
          </PieChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Events Timeline">
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
            <XAxis
              dataKey="time"
              stroke={colors.text}
              fontSize={12}
              tickLine={false}
              axisLine={false}
              tickFormatter={(value) => new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            />
            <YAxis stroke={colors.text} fontSize={12} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "#F8FAFC" }} labelStyle={{ color: "#94A3B8" }} />
            <Line
              type="monotone"
              dataKey="count"
              stroke={colors.blue}
              strokeWidth={3}
              dot={false}
              activeDot={{ r: 6, fill: colors.blue, stroke: "#0F172A", strokeWidth: 2 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </ChartCard>
    </div>
  );
}

function ChartCard({ title, children }) {
  return (
    <div style={glassCardStyle}>
      <h3 style={cardTitleStyle}>{title}</h3>
      {children}
    </div>
  );
}

// --- Styles ---

const panelGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))",
  gap: "24px",
  marginBottom: "32px",
};

const glassCardStyle = {
  background: "rgba(255, 255, 255, 0.02)",
  border: "1px solid rgba(255, 255, 255, 0.08)",
  borderRadius: "16px",
  padding: "24px",
  backdropFilter: "blur(12px)",
  WebkitBackdropFilter: "blur(12px)",
  fontFamily: "system-ui, -apple-system, sans-serif",
};

const cardTitleStyle = {
  margin: "0 0 24px 0",
  fontSize: "0.875rem",
  fontWeight: "500",
  color: "#A1A1AA",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
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

export default ChartsPanel;