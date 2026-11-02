import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";

delete L.Icon.Default.prototype._getIconUrl;

L.Icon.Default.mergeOptions({
  iconRetinaUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
});

function AttackMap({ locations }) {
  return (
    <div style={glassCardStyle}>
      <h3 style={cardTitleStyle}>Global Attack Origins</h3>

      <div style={mapWrapperStyle}>
        <MapContainer
          center={[20, 0]}
          zoom={2}
          scrollWheelZoom={false}
          style={{ height: "100%", width: "100%", background: "#0F172A" }} // Dark background fallback
        >
          {/* Using a darker CartoDB style map tile for a more premium dark mode look instead of default OSM */}
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/attributions">CARTO</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />

          {locations.map((location) => (
            <Marker
              key={location.session_id}
              position={[location.latitude, location.longitude]}
            >
              <Popup className="premium-popup">
                <strong style={{ display: "block", marginBottom: "4px", fontSize: "0.875rem" }}>
                  {location.attacker_ip}
                </strong>
                <div style={{ color: "#64748B", fontSize: "0.75rem", lineHeight: "1.5" }}>
                  {location.city || "-"}, {location.country || "-"}
                  <br />
                  ASN: {location.asn || "-"}
                  <br />
                  Org: {location.organization || "-"}
                  <br />
                  <span style={{ color: "#F87171", fontWeight: "500", marginTop: "4px", display: "inline-block" }}>
                    Threat Score: {location.threat_score || 0}
                  </span>
                </div>
              </Popup>
            </Marker>
          ))}
        </MapContainer>
      </div>
    </div>
  );
}

// --- Styles ---

const glassCardStyle = {
  background: "rgba(255, 255, 255, 0.02)",
  border: "1px solid rgba(255, 255, 255, 0.08)",
  borderRadius: "16px",
  padding: "24px",
  marginBottom: "32px",
  backdropFilter: "blur(12px)",
  WebkitBackdropFilter: "blur(12px)",
  fontFamily: "system-ui, -apple-system, sans-serif",
};

const cardTitleStyle = {
  margin: "0 0 24px 0",
  fontSize: "1.125rem",
  fontWeight: "500",
  color: "#F8FAFC",
  letterSpacing: "-0.01em",
};

const mapWrapperStyle = {
  height: "480px",
  width: "100%",
  borderRadius: "12px",
  overflow: "hidden", // Forces the map to respect the curved corners
  border: "1px solid rgba(255, 255, 255, 0.05)",
  position: "relative",
  zIndex: 1, // Fixes leaflet corner clipping bugs
};

export default AttackMap;