import React, { useState, useEffect } from "react";
import { MapContainer, TileLayer, Marker, Popup, Circle } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";
import toast, { Toaster } from "react-hot-toast";

// Fix for default markers in react-leaflet
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: require("leaflet/dist/images/marker-icon-2x.png"),
  iconUrl: require("leaflet/dist/images/marker-icon.png"),
  shadowUrl: require("leaflet/dist/images/marker-shadow.png"),
});

// Professional color scheme
const colors = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#16a34a",
  minimal: "#059669",
  primary: "#1e40af",
  secondary: "#64748b",
  background: "#f8fafc",
  surface: "#ffffff",
  border: "#e2e8f0",
};

const categoryColors = {
  "Potentially Bad Traffic": "#a855f7",
  "Policy Violation": "#0d9488",
  "Malware": "#ec4899",
  "Attempted Information Leak": "#4f46e5",
  "Unknown": "#6b7280",
};

const RealTimeRiskMap = () => {
  const [riskData, setRiskData] = useState([]);
  const [statistics, setStatistics] = useState({});
  const [selectedIP, setSelectedIP] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [sortBy, setSortBy] = useState("risk_score");
  const [searchQuery, setSearchQuery] = useState("");
  const [isHighRiskCollapsed, setIsHighRiskCollapsed] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(5);
  const [error, setError] = useState(null);

  const API_BASE_URL = "http://34.222.107.115:8000";

  const fetchRiskData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/risk/top_risks`);
      if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
      const data = await response.json();
      setRiskData(data.top_risks || []);
      setCurrentPage(1);
      console.log("Fetched risk data:", data.top_risks);
    } catch (error) {
      console.error("Failed to fetch risk data:", error);
      setError("Failed to fetch risk data. Please check the backend.");
    } finally {
      setIsLoading(false);
    }
  };

  const fetchStatistics = async () => {
    setError(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/risk/statistics`);
      if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
      const data = await response.json();
      setStatistics(data);
      console.log("Fetched statistics:", data);
    } catch (error) {
      console.error("Failed to fetch statistics:", error);
      setError("Failed to fetch statistics. Please check the backend.");
    }
  };

  const analyzeIP = async (ip) => {
    setError(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/risk/analyze/${ip}`);
      if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
      const data = await response.json();
      setSelectedIP(data);
      console.log(`Analyzed IP ${ip}:`, data);
    } catch (error) {
      console.error(`Failed to analyze IP ${ip}:`, error);
      setError(`Failed to analyze IP ${ip}.`);
    }
  };

  const simulateTraffic = async (ip) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/risk/simulate/${ip}`, { method: "POST" });
      if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
      const data = await response.json();
      toast.success(data.message, { duration: 3000 });
      console.log(`Traffic simulation for ${ip}:`, data);
      setTimeout(() => {
        fetchRiskData();
        fetchStatistics();
      }, 1000);
    } catch (error) {
      console.error(`Failed to simulate traffic for ${ip}:`, error);
      toast.error(`Failed to simulate traffic for ${ip}: ${error.message}`, { duration: 5000 });
    }
  };

  const getMarkerColor = (threatLevel) => {
    switch (threatLevel) {
      case "CRITICAL": return colors.critical;
      case "HIGH": return colors.high;
      case "MEDIUM": return colors.medium;
      case "LOW": return colors.low;
      default: return colors.minimal;
    }
  };

  const getThreatBadgeStyle = (threatLevel) => {
    const baseStyle = {
      padding: "3px 8px",
      borderRadius: "10px",
      fontSize: "10px",
      fontWeight: "600",
      textTransform: "uppercase",
      letterSpacing: "0.5px",
    };
    switch (threatLevel) {
      case "CRITICAL": return { ...baseStyle, background: colors.critical, color: "white" };
      case "HIGH": return { ...baseStyle, background: colors.high, color: "white" };
      case "MEDIUM": return { ...baseStyle, background: colors.medium, color: "white" };
      case "LOW": return { ...baseStyle, background: colors.low, color: "white" };
      default: return { ...baseStyle, background: colors.minimal, color: "white" };
    }
  };

  const getCategoryColor = (category) => {
    return categoryColors[category] || categoryColors["Unknown"];
  };

  const getRiskRadius = (riskScore) => {
    return Math.max(riskScore * 100000, 10000);
  };

  const filteredRiskData = riskData
    .filter(
      (risk) =>
        risk.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
        risk.country.toLowerCase().includes(searchQuery.toLowerCase())
    )
    .sort((a, b) => {
      if (sortBy === "risk_score") return b.risk_score - a.risk_score;
      if (sortBy === "threat_level") {
        const levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"];
        return levels.indexOf(a.threat_level) - levels.indexOf(b.threat_level);
      }
      return new Date(b.last_seen) - new Date(a.last_seen);
    });

  const totalItems = filteredRiskData.length;
  const totalPages = Math.ceil(totalItems / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedRiskData = filteredRiskData.slice(startIndex, endIndex);

  const goToPage = (page) => {
    setCurrentPage(Math.min(Math.max(1, page), totalPages));
  };

  useEffect(() => {
    fetchRiskData();
    fetchStatistics();
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(() => {
        console.log("Auto-refresh triggered");
        fetchRiskData();
        fetchStatistics();
      }, 10000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        flexDirection: "column",
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
      }}
    >
      <Toaster position="top-right" />
      {/* Header */}
      <div
        style={{
          background: "linear-gradient(135deg, #1e40af 0%, #3730a3 100%)",
          color: "white",
          padding: "16px 24px",
          boxShadow: "0 4px 6px rgba(0, 0, 0, 0.1)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <h1 style={{ margin: 0, fontSize: "20px", fontWeight: "600" }}>
            Real-Time IP Geolocation Risk Assessment
          </h1>
          {isLoading && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                background: "rgba(255,255,255,0.2)",
                padding: "4px 12px",
                borderRadius: "16px",
                fontSize: "12px",
              }}
            >
              <div
                style={{
                  width: "12px",
                  height: "12px",
                  border: "2px solid transparent",
                  borderTop: "2px solid white",
                  borderRadius: "50%",
                  animation: "spin 1s linear infinite",
                  marginRight: "6px",
                }}
              ></div>
              Loading...
            </div>
          )}
        </div>
        {error && (
          <div
            style={{
              background: colors.critical,
              padding: "8px",
              borderRadius: "6px",
              marginTop: "8px",
              fontSize: "13px",
            }}
          >
            {error}
          </div>
        )}
        <div
          style={{
            display: "flex",
            marginTop: "12px",
            gap: "12px",
            flexWrap: "wrap",
          }}
        >
          <div
            style={{
              background: "rgba(255,255,255,0.15)",
              padding: "6px 12px",
              borderRadius: "6px",
              fontSize: "13px",
              fontWeight: "500",
              backdropFilter: "blur(10px)",
            }}
          >
            Total IPs: {statistics.total_ips || 0}
          </div>
          <div
            style={{
              background: "rgba(255,255,255,0.15)",
              padding: "6px 12px",
              borderRadius: "6px",
              fontSize: "13px",
              fontWeight: "500",
              backdropFilter: "blur(10px)",
            }}
          >
            Avg Risk: {(statistics.average_risk_score || 0).toFixed(3)}
          </div>
          <div
            style={{
              background: colors.critical,
              padding: "6px 12px",
              borderRadius: "6px",
              fontSize: "13px",
              fontWeight: "500",
            }}
          >
            Critical: {statistics.threat_levels?.CRITICAL || 0}
          </div>
          <div
            style={{
              background: colors.high,
              padding: "6px 12px",
              borderRadius: "6px",
              fontSize: "13px",
              fontWeight: "500",
            }}
          >
            High: {statistics.threat_levels?.HIGH || 0}
          </div>
          <div
            style={{
              background: colors.medium,
              padding: "6px 12px",
              borderRadius: "6px",
              fontSize: "13px",
              fontWeight: "500",
            }}
          >
            Medium: {statistics.threat_levels?.MEDIUM || 0}
          </div>
          <div
            style={{
              background: colors.low,
              padding: "6px 12px",
              borderRadius: "6px",
              fontSize: "13px",
              fontWeight: "500",
            }}
          >
            Low: {statistics.threat_levels?.LOW || 0}
          </div>
        </div>
      </div>

      {/* Controls */}
      <div
        style={{
          background: colors.surface,
          padding: "12px 24px",
          borderBottom: `1px solid ${colors.border}`,
          display: "flex",
          gap: "16px",
          alignItems: "center",
          flexWrap: "wrap",
          boxShadow: "0 1px 3px rgba(0, 0, 0, 0.1)",
        }}
      >
        <button
          onClick={() => {
            fetchRiskData();
            toast("Refreshing data...", { duration: 2000 });
          }}
          style={{
            background: colors.primary,
            color: "white",
            border: "none",
            padding: "8px 16px",
            borderRadius: "6px",
            cursor: "pointer",
            fontSize: "14px",
            fontWeight: "500",
            transition: "all 0.2s ease",
          }}
          onMouseEnter={(e) => (e.target.style.transform = "translateY(-1px)")}
          onMouseLeave={(e) => (e.target.style.transform = "translateY(0)")}
        >
          Refresh Data
        </button>

        <label
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            fontSize: "14px",
            color: colors.secondary,
            fontWeight: "500",
          }}
        >
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
            style={{ transform: "scale(1.2)" }}
          />
          Auto Refresh (10s)
        </label>

        <div style={{ display: "flex", gap: "8px" }}>
          <button
            onClick={() => simulateTraffic("114.114.114.114")}
            style={{
              background: colors.high,
              color: "white",
              border: "none",
              padding: "6px 12px",
              borderRadius: "4px",
              cursor: "pointer",
              fontSize: "12px",
              fontWeight: "500",
            }}
          >
            Test China IP
          </button>

          <button
            onClick={() => simulateTraffic("192.168.1.100")}
            style={{
              background: colors.medium,
              color: "white",
              border: "none",
              padding: "6px 12px",
              borderRadius: "4px",
              cursor: "pointer",
              fontSize: "12px",
              fontWeight: "500",
            }}
          >
            Test Private IP
          </button>

          <button
            onClick={() => simulateTraffic("8.8.8.8")}
            style={{
              background: colors.low,
              color: "white",
              border: "none",
              padding: "6px 12px",
              borderRadius: "4px",
              cursor: "pointer",
              fontSize: "12px",
              fontWeight: "500",
            }}
          >
            Test US IP
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, display: "flex" }}>
        {/* Map */}
        <div style={{ flex: 2 }}>
          <MapContainer
            center={[40.7128, -74.006]}
            zoom={2}
            style={{ height: "100%", width: "100%" }}
          >
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            {paginatedRiskData.map(
              (risk, index) =>
                risk.latitude &&
                risk.longitude && (
                  <div key={index}>
                    <Circle
                      center={[risk.latitude, risk.longitude]}
                      radius={getRiskRadius(risk.risk_score)}
                      pathOptions={{
                        color: getMarkerColor(risk.threat_level),
                        fillColor: getMarkerColor(risk.threat_level),
                        fillOpacity: 0.2,
                        weight: 2,
                      }}
                    />
                    <Marker
                      position={[risk.latitude, risk.longitude]}
                      eventHandlers={{
                        click: () => analyzeIP(risk.ip),
                      }}
                    >
                      <Popup>
                        <div
                          style={{
                            minWidth: "220px",
                            fontFamily: "'Segoe UI', sans-serif",
                          }}
                        >
                          <div
                            style={{
                              fontWeight: "600",
                              fontSize: "16px",
                              marginBottom: "8px",
                              color: colors.primary,
                            }}
                          >
                            {risk.ip}
                          </div>
                          <div
                            style={{
                              fontSize: "14px",
                              color: colors.secondary,
                              marginBottom: "4px",
                            }}
                          >
                            <strong>Location:</strong> {risk.country}
                          </div>
                          <div
                            style={{
                              fontSize: "14px",
                              color: colors.secondary,
                              marginBottom: "4px",
                            }}
                          >
                            <strong>Risk Score:</strong>{" "}
                            {risk.risk_score.toFixed(3)}
                          </div>
                          <div
                            style={{
                              fontSize: "14px",
                              color: colors.secondary,
                              marginBottom: "8px",
                            }}
                          >
                            <strong>Threat Level:</strong>
                            <span style={getThreatBadgeStyle(risk.threat_level)}>
                              {risk.threat_level}
                            </span>
                          </div>
                          <div
                            style={{
                              fontSize: "12px",
                              color: colors.secondary,
                            }}
                          >
                            <strong>Last Seen:</strong>{" "}
                            {new Date(risk.last_seen).toLocaleString()}
                          </div>
                        </div>
                      </Popup>
                    </Marker>
                  </div>
                )
            )}
          </MapContainer>
        </div>

        {/* Side Panel */}
        <div
          style={{
            flex: 1,
            background: colors.background,
            borderLeft: `1px solid ${colors.border}`,
            padding: "24px",
            overflowY: "auto",
          }}
        >
          <div style={{ marginBottom: "24px" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "16px",
              }}
            >
              <h3
                style={{
                  color: colors.critical,
                  fontSize: "18px",
                  fontWeight: "600",
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                }}
              >
                <div
                  style={{
                    width: "8px",
                    height: "8px",
                    borderRadius: "50%",
                    background: colors.critical,
                  }}
                ></div>
                High-Risk IPs ({filteredRiskData.length})
              </h3>
              <button
                onClick={() => setIsHighRiskCollapsed(!isHighRiskCollapsed)}
                style={{
                  color: colors.primary,
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  fontSize: "14px",
                }}
              >
                {isHighRiskCollapsed ? "Expand" : "Collapse"}
              </button>
            </div>

            {!isHighRiskCollapsed && (
              <>
                <div
                  style={{
                    display: "flex",
                    gap: "12px",
                    marginBottom: "16px",
                    flexWrap: "wrap",
                  }}
                >
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => {
                      setSearchQuery(e.target.value);
                      setCurrentPage(1);
                    }}
                    placeholder="Search by IP or country"
                    style={{
                      padding: "6px 12px",
                      border: `1px solid ${colors.border}`,
                      borderRadius: "6px",
                      fontSize: "14px",
                      width: "200px",
                    }}
                  />
                  <select
                    value={sortBy}
                    onChange={(e) => {
                      setSortBy(e.target.value);
                      setCurrentPage(1);
                    }}
                    style={{
                      padding: "6px 12px",
                      border: `1px solid ${colors.border}`,
                      borderRadius: "6px",
                      fontSize: "14px",
                    }}
                  >
                    <option value="risk_score">Sort by Risk Score</option>
                    <option value="threat_level">Sort by Threat Level</option>
                    <option value="last_seen">Sort by Last Seen</option>
                  </select>
                  <select
                    value={itemsPerPage}
                    onChange={(e) => {
                      setItemsPerPage(Number(e.target.value));
                      setCurrentPage(1);
                    }}
                    style={{
                      padding: "6px 12px",
                      border: `1px solid ${colors.border}`,
                      borderRadius: "6px",
                      fontSize: "14px",
                    }}
                  >
                    <option value={5}>5 per page</option>
                    <option value={10}>10 per page</option>
                    <option value={20}>20 per page</option>
                  </select>
                </div>

                {paginatedRiskData.map((risk, index) => (
                  <div
                    key={index}
                    style={{
                      background: colors.surface,
                      border: `1px solid ${colors.border}`,
                      borderLeft: `4px solid ${getMarkerColor(risk.threat_level)}`,
                      borderRadius: "8px",
                      padding: "12px",
                      marginBottom: "10px",
                      cursor: "pointer",
                      transition: "all 0.2s ease",
                      boxShadow: "0 1px 3px rgba(0, 0, 0, 0.1)",
                    }}
                    onClick={() => analyzeIP(risk.ip)}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.transform = "scale(1.02)";
                      e.currentTarget.style.boxShadow =
                        "0 4px 12px rgba(0, 0, 0, 0.15)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.transform = "scale(1)";
                      e.currentTarget.style.boxShadow =
                        "0 1px 3px rgba(0, 0, 0, 0.1)";
                    }}
                    title={`IP: ${risk.ip}\nCountry: ${risk.country}`}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                        marginBottom: "6px",
                      }}
                    >
                      <div
                        style={{
                          width: "6px",
                          height: "6px",
                          borderRadius: "50%",
                          background: getCategoryColor(risk.category || "Unknown"),
                        }}
                      ></div>
                      <span
                        style={{
                          fontWeight: "600",
                          fontSize: "14px",
                          color: colors.primary,
                          cursor: "pointer",
                        }}
                        onClick={(e) => {
                          e.stopPropagation();
                          analyzeIP(risk.ip);
                        }}
                      >
                        {risk.ip}
                      </span>
                    </div>
                    <div
                      style={{
                        fontSize: "12px",
                        color: colors.secondary,
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: "6px",
                      }}
                    >
                      <span>{risk.country}</span>
                      <span style={{ fontWeight: "500" }}>
                        Score: {risk.risk_score.toFixed(3)}
                      </span>
                    </div>
                    <div
                      style={{
                        display: "flex",
                        gap: "8px",
                        alignItems: "center",
                      }}
                    >
                      <span style={getThreatBadgeStyle(risk.threat_level)}>
                        {risk.threat_level}
                      </span>
                      <span
                        style={{
                          padding: "3px 8px",
                          borderRadius: "10px",
                          fontSize: "10px",
                          fontWeight: "600",
                          background: getCategoryColor(risk.category || "Unknown"),
                          color: "white",
                        }}
                      >
                        {risk.category || "Unknown"}
                      </span>
                      <span
                        style={{
                          fontSize: "10px",
                          color: colors.secondary,
                        }}
                      >
                        Alerts: {risk.alert_count || 0}
                      </span>
                    </div>
                  </div>
                ))}

                {totalItems > 0 && (
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginTop: "12px",
                      fontSize: "12px",
                      color: colors.secondary,
                    }}
                  >
                    <div>
                      Showing {startIndex + 1}-
                      {Math.min(endIndex, totalItems)} of {totalItems} IPs
                    </div>
                    <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                      <button
                        onClick={() => goToPage(1)}
                        disabled={currentPage === 1}
                        style={{
                          background: currentPage === 1 ? colors.border : colors.primary,
                          color: "white",
                          border: "none",
                          padding: "4px 8px",
                          borderRadius: "4px",
                          cursor: currentPage === 1 ? "not-allowed" : "pointer",
                          fontSize: "12px",
                        }}
                      >
                        First
                      </button>
                      <button
                        onClick={() => goToPage(currentPage - 1)}
                        disabled={currentPage === 1}
                        style={{
                          background: currentPage === 1 ? colors.border : colors.primary,
                          color: "white",
                          border: "none",
                          padding: "4px 8px",
                          borderRadius: "4px",
                          cursor: currentPage === 1 ? "not-allowed" : "pointer",
                          fontSize: "12px",
                        }}
                      >
                        Prev
                      </button>
                      <span>
                        Page {currentPage} of {totalPages}
                      </span>
                      <button
                        onClick={() => goToPage(currentPage + 1)}
                        disabled={currentPage === totalPages}
                        style={{
                          background: currentPage === totalPages ? colors.border : colors.primary,
                          color: "white",
                          border: "none",
                          padding: "4px 8px",
                          borderRadius: "4px",
                          cursor: currentPage === totalPages ? "not-allowed" : "pointer",
                          fontSize: "12px",
                        }}
                      >
                        Next
                      </button>
                      <button
                        onClick={() => goToPage(totalPages)}
                        disabled={currentPage === totalPages}
                        style={{
                          background: currentPage === totalPages ? colors.border : colors.primary,
                          color: "white",
                          border: "none",
                          padding: "4px 8px",
                          borderRadius: "4px",
                          cursor: currentPage === totalPages ? "not-allowed" : "pointer",
                          fontSize: "12px",
                        }}
                      >
                        Last
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>

          {selectedIP && (
            <div
              style={{
                background: colors.surface,
                border: `1px solid ${colors.border}`,
                borderRadius: "12px",
                padding: "20px",
                boxShadow: "0 4px 12px rgba(0, 0, 0, 0.1)",
              }}
            >
              <h4
                style={{
                  color: colors.primary,
                  marginBottom: "16px",
                  fontSize: "18px",
                  fontWeight: "600",
                  borderBottom: `2px solid ${colors.primary}`,
                  paddingBottom: "8px",
                }}
              >
                IP Analysis: {selectedIP.ip}
              </h4>
              <div style={{ fontSize: "14px", lineHeight: "1.6" }}>
                <div
                  style={{
                    marginBottom: "12px",
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "12px",
                  }}
                >
                  <div>
                    <strong style={{ color: colors.secondary }}>Location:</strong>
                    <div style={{ marginTop: "4px" }}>
                      {selectedIP.city}, {selectedIP.country}
                    </div>
                  </div>
                  <div>
                    <strong style={{ color: colors.secondary }}>Connections:</strong>
                    <div style={{ marginTop: "4px" }}>{selectedIP.connection_count}</div>
                  </div>
                </div>
                <div
                  style={{
                    marginBottom: "12px",
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "12px",
                  }}
                >
                  <div>
                    <strong style={{ color: colors.secondary }}>Risk Score:</strong>
                    <div
                      style={{
                        marginTop: "4px",
                        fontSize: "18px",
                        fontWeight: "600",
                        color: getMarkerColor(selectedIP.threat_level),
                      }}
                    >
                      {selectedIP.risk_score.toFixed(3)}
                    </div>
                  </div>
                  <div>
                    <strong style={{ color: colors.secondary }}>Threat Level:</strong>
                    <div style={{ marginTop: "4px" }}>
                      <span style={getThreatBadgeStyle(selectedIP.threat_level)}>
                        {selectedIP.threat_level}
                      </span>
                    </div>
                  </div>
                </div>
                <div style={{ marginTop: "16px" }}>
                  <strong style={{ color: colors.secondary, fontSize: "16px" }}>
                    Risk Factors:
                  </strong>
                  {selectedIP.risk_factors.map((factor, idx) => (
                    <div
                      key={idx}
                      style={{
                        background: colors.background,
                        padding: "12px",
                        margin: "8px 0",
                        borderRadius: "8px",
                        border: `1px solid ${colors.border}`,
                        fontSize: "13px",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          marginBottom: "4px",
                        }}
                      >
                        <span style={{ fontWeight: "600", color: colors.primary }}>
                          {factor.name}
                        </span>
                        <span
                          style={{
                            fontWeight: "600",
                            color: getMarkerColor(factor.score > 0.5 ? "HIGH" : "LOW"),
                          }}
                        >
                          {factor.score.toFixed(3)}
                        </span>
                      </div>
                      <div style={{ color: colors.secondary, marginBottom: "4px" }}>
                        {factor.description}
                      </div>
                      <div
                        style={{
                          fontSize: "11px",
                          color: colors.low,
                          display: "flex",
                          alignItems: "center",
                          gap: "4px",
                        }}
                      >
                        <div
                          style={{
                            width: "8px",
                            height: "8px",
                            borderRadius: "50%",
                            background: colors.low,
                          }}
                        ></div>
                        Confidence: {(factor.confidence * 100).toFixed(0)}%
                      </div>
                    </div>
                  ))}
                </div>
                {selectedIP.suspicious_activities.length > 0 && (
                  <div style={{ marginTop: "16px" }}>
                    <strong style={{ color: colors.critical, fontSize: "16px" }}>
                      Suspicious Activities:
                    </strong>
                    <div
                      style={{
                        background: "#fef2f2",
                        border: `1px solid ${colors.critical}`,
                        borderRadius: "8px",
                        padding: "12px",
                        marginTop: "8px",
                      }}
                    >
                      {selectedIP.suspicious_activities.map((activity, idx) => (
                        <div
                          key={idx}
                          style={{
                            fontSize: "13px",
                            color: colors.critical,
                            marginBottom: "4px",
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                          }}
                        >
                          <div
                            style={{
                              width: "4px",
                              height: "4px",
                              borderRadius: "50%",
                              background: colors.critical,
                            }}
                          ></div>
                          {activity}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <div style={{ marginTop: "20px", display: "flex", gap: "12px" }}>
                <button
                  onClick={() => simulateTraffic(selectedIP.ip)}
                  style={{
                    background: colors.medium,
                    color: "white",
                    border: "none",
                    padding: "8px 16px",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontSize: "13px",
                    fontWeight: "500",
                  }}
                >
                  Simulate Traffic
                </button>
                <button
                  onClick={() => setSelectedIP(null)}
                  style={{
                    background: colors.secondary,
                    color: "white",
                    border: "none",
                    padding: "8px 16px",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontSize: "13px",
                    fontWeight: "500",
                  }}
                >
                  Close Analysis
                </button>
              </div>
            </div>
          )}
          <div
            style={{
              background: colors.surface,
              border: `1px solid ${colors.border}`,
              borderRadius: "12px",
              padding: "20px",
              marginTop: "20px",
              boxShadow: "0 4px 12px rgba(0, 0, 0, 0.1)",
            }}
          >
            <h5
              style={{
                color: colors.primary,
                marginBottom: "16px",
                fontSize: "16px",
                fontWeight: "600",
                borderBottom: `2px solid ${colors.primary}`,
                paddingBottom: "8px",
              }}
            >
              Threat Level Classification
            </h5>
            <div
              style={{
                fontSize: "13px",
                display: "flex",
                flexDirection: "column",
                gap: "8px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center" }}>
                <div
                  style={{
                    width: "16px",
                    height: "16px",
                    background: colors.critical,
                    borderRadius: "50%",
                    marginRight: "12px",
                    boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
                  }}
                ></div>
                <span style={{ color: colors.secondary, fontWeight: "500" }}>
                  CRITICAL (Risk ≥ 0.8)
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center" }}>
                <div
                  style={{
                    width: "16px",
                    height: "16px",
                    background: colors.high,
                    borderRadius: "50%",
                    marginRight: "12px",
                    boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
                  }}
                ></div>
                <span style={{ color: colors.secondary, fontWeight: "500" }}>
                  HIGH (Risk 0.6-0.8)
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center" }}>
                <div
                  style={{
                    width: "16px",
                    height: "16px",
                    background: colors.medium,
                    borderRadius: "50%",
                    marginRight: "12px",
                    boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
                  }}
                ></div>
                <span style={{ color: colors.secondary, fontWeight: "500" }}>
                  MEDIUM (Risk 0.4-0.6)
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center" }}>
                <div
                  style={{
                    width: "16px",
                    height: "16px",
                    background: colors.low,
                    borderRadius: "50%",
                    marginRight: "12px",
                    boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
                  }}
                ></div>
                <span style={{ color: colors.secondary, fontWeight: "500" }}>
                  LOW (Risk 0.2-0.4)
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center" }}>
                <div
                  style={{
                    width: "16px",
                    height: "16px",
                    background: colors.minimal,
                    borderRadius: "50%",
                    marginRight: "12px",
                    boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
                  }}
                ></div>
                <span style={{ color: colors.secondary, fontWeight: "500" }}>
                  MINIMAL (Risk less than 0.2)
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
      <style jsx global>{`
        @keyframes spin {
          0% {
            transform: rotate(0deg);
          }
          100% {
            transform: rotate(360deg);
          }
        }
      `}</style>
    </div>
  );
};

export default RealTimeRiskMap;