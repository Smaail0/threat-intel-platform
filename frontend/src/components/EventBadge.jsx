function EventBadge({ type }) {
  const themes = {
    success: { bg: "rgba(34, 197, 94, 0.1)", color: "#4ADE80", border: "rgba(34, 197, 94, 0.2)" },
    failed:  { bg: "rgba(239, 68, 68, 0.1)", color: "#F87171", border: "rgba(239, 68, 68, 0.2)" },
    input:   { bg: "rgba(245, 158, 11, 0.1)", color: "#FBBF24", border: "rgba(245, 158, 11, 0.2)" },
    connect: { bg: "rgba(59, 130, 246, 0.1)", color: "#60A5FA", border: "rgba(59, 130, 246, 0.2)" },
    default: { bg: "rgba(255, 255, 255, 0.05)", color: "#A1A1AA", border: "rgba(255, 255, 255, 0.1)" }
  };

  let activeTheme = themes.default;
  if (type.includes("login.success")) activeTheme = themes.success;
  if (type.includes("login.failed")) activeTheme = themes.failed;
  if (type.includes("command.input")) activeTheme = themes.input;
  if (type.includes("session.connect")) activeTheme = themes.connect;

  return (
    <span style={{
      background: activeTheme.bg,
      color: activeTheme.color,
      border: `1px solid ${activeTheme.border}`,
      padding: "4px 10px",
      borderRadius: "6px",
      fontSize: "0.75rem",
      fontWeight: "500",
      letterSpacing: "0.02em",
      fontFamily: "system-ui, -apple-system, sans-serif",
      whiteSpace: "nowrap"
    }}>
      {type}
    </span>
  );
}

export default EventBadge;