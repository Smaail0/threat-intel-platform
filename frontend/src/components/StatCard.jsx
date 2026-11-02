function StatCard({ title, value }) {
  return (
    <div style={{
      background: "rgba(255, 255, 255, 0.02)",
      border: "1px solid rgba(255, 255, 255, 0.08)",
      padding: "24px",
      borderRadius: "16px",
      minWidth: "180px",
      display: "flex",
      flexDirection: "column",
      gap: "8px",
      backdropFilter: "blur(12px)",
      WebkitBackdropFilter: "blur(12px)", // For Safari support
    }}>
      <h3 style={{
        margin: 0,
        fontSize: "0.875rem",
        fontWeight: "500",
        color: "#A1A1AA", // Muted slate gray
        textTransform: "uppercase",
        letterSpacing: "0.05em",
        fontFamily: "system-ui, -apple-system, sans-serif"
      }}>
        {title}
      </h3>

      <p style={{
        margin: 0,
        fontSize: "2.5rem",
        fontWeight: "600",
        color: "#F8FAFC",
        fontFamily: "system-ui, -apple-system, sans-serif",
        letterSpacing: "-0.02em"
      }}>
        {value}
      </p>
    </div>
  );
}

export default StatCard;