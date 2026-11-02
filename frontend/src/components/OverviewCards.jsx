import StatCard from "./StatCard";

function OverviewCards({ overview }) {
  if (!overview) return null;

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
      gap: "24px",
      marginTop: "2rem",
      marginBottom: "2rem"
    }}>
      <StatCard
        title="Sessions"
        value={overview.total_sessions}
      />
      <StatCard
        title="Events"
        value={overview.total_events}
      />
      <StatCard
        title="Attackers"
        value={overview.unique_attackers}
      />
      <StatCard
        title="Successful Logins"
        value={overview.successful_logins}
      />
    </div>
  );
}

export default OverviewCards;