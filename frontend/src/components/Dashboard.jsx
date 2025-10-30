import React, { useState, useEffect } from "react";

const protoMap = { 1: "ICMP", 6: "TCP", 17: "UDP" };

// Helper functions
const getAnomalyColor = (anomaly) => {
  if (anomaly >= 0.8) return "bg-red-100 text-red-800";
  if (anomaly >= 0.5) return "bg-orange-100 text-orange-800";
  return "bg-green-100 text-green-800";
};

const Dashboard = () => {
  const [stats, setStats] = useState({});
  const [liveThreats, setLiveThreats] = useState([]);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [searchIP, setSearchIP] = useState("");
  const [searchResults, setSearchResults] = useState([]);
  const [loading, setLoading] = useState(true);

  const BASE_URL = "http://34.222.107.115:8000/api"; // Backend URL

  // Fetch Dashboard stats
  const fetchStats = async () => {
    try {
      const res = await fetch(`${BASE_URL}/dashboard_stats`);
      const data = await res.json();
      setStats(data);
    } catch (err) {
      console.error("Error fetching stats:", err);
    }
  };

  // Fetch Live Threats
  const fetchLiveThreats = async () => {
    try {
      const res = await fetch(`${BASE_URL}/live_threats`);
      const data = await res.json();
      setLiveThreats(data.malicious_ips);
    } catch (err) {
      console.error("Error fetching live threats:", err);
    }
  };

  // Fetch Blocked IPs
  const fetchBlockedIPs = async () => {
    try {
      const res = await fetch(`${BASE_URL}/blocked_ips`);
      const data = await res.json();
      const formatted = data.blocked_ips.map((ip) => ({
        src_ip: ip,
        dest_ip: "-",
        proto: "-",
        attack_type: "Blocked",
        timestamp: "-", // Replace with real timestamp if available
      }));
      setBlockedIPs(formatted);
    } catch (err) {
      console.error("Error fetching blocked IPs:", err);
    }
  };

  useEffect(() => {
    const fetchAll = async () => {
      await Promise.all([fetchStats(), fetchLiveThreats(), fetchBlockedIPs()]);
      setLoading(false);
    };
    fetchAll();
  }, []);

  // IP Search
  const handleSearch = async () => {
    if (!searchIP) return;
    try {
      const res = await fetch(`${BASE_URL}/ip/search/${searchIP}`);
      if (res.status === 404) {
        setSearchResults([]);
      } else {
        const data = await res.json();
        setSearchResults(data.logs);
      }
    } catch (err) {
      console.error("Error searching IP:", err);
    }
  };

  if (loading) return <p className="p-6">Loading dashboard...</p>;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <h1 className="text-3xl font-bold mb-6">Enterprise AI-IDPS Dashboard</h1>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-sm font-medium text-gray-500">Total Alerts</h3>
          <p className="text-3xl font-bold text-blue-600">{stats.total_alerts}</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-sm font-medium text-gray-500">High Priority</h3>
          <p className="text-3xl font-bold text-red-600">{stats.high_severity_alerts}</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-sm font-medium text-gray-500">Recent Threats</h3>
          <p className="text-3xl font-bold text-orange-600">{stats.recent_alerts}</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-sm font-medium text-gray-500">Blocked IPs</h3>
          <p className="text-3xl font-bold text-purple-600">{stats.blocked_ips}</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-sm font-medium text-gray-500">Live Threats</h3>
          <p className="text-3xl font-bold text-red-600">{stats.live_threat_count}</p>
        </div>
      </div>

      {/* Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Live Threats */}
        <div className="bg-white p-6 rounded-lg shadow-md border">
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <div className="w-3 h-3 bg-red-600 rounded-full mr-2"></div>Live Threats
          </h3>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {liveThreats.map((t, idx) => (
              <div key={idx} className="flex justify-between items-center p-2 rounded border border-gray-200">
                <div className="flex flex-col text-sm">
                  <span>{t.src_ip} → {t.dest_ip}:{t.dest_port || "-"}</span>
                  <span>Proto: {t.proto} ({protoMap[t.proto_code] || "Unknown"})</span>
                  <span>Attack: {t.attack_type}</span>
                  <span>Timestamp: {t.timestamp}</span>
                  <span>Country: {t.country || "-"}</span>
                </div>
                <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${getAnomalyColor(t.anomaly || 0)}`}>
                  {(t.anomaly || 0).toFixed(2)}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Blocked IPs */}
        <div className="bg-white p-6 rounded-lg shadow-md border">
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <div className="w-3 h-3 bg-purple-600 rounded-full mr-2"></div>Blocked IPs
          </h3>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {blockedIPs.map((ip, idx) => (
              <div
                key={idx}
                className="flex justify-between items-center border-l-2 border-purple-400 bg-purple-50 p-2 rounded-r text-sm"
              >
                <div className="flex flex-col">
                  <span>{ip.src_ip}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* IP Search */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h3 className="text-lg font-semibold mb-4">Search IP Logs</h3>
        <div className="flex space-x-2 mb-4">
          <input
            type="text"
            value={searchIP}
            onChange={(e) => setSearchIP(e.target.value)}
            placeholder="Enter IP address"
            className="flex-1 px-3 py-2 border border-gray-300 rounded-md text-sm"
          />
          <button
            onClick={handleSearch}
            className="px-4 py-2 bg-blue-600 text-white rounded-md text-sm hover:bg-blue-700"
          >
            Search
          </button>
        </div>
        {searchResults.length === 0 ? (
          <p className="text-gray-500">No logs found for this IP</p>
        ) : (
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {searchResults.map((log, idx) => (
              <div key={idx} className="flex justify-between items-center p-2 rounded border border-gray-200">
                <div className="flex flex-col text-sm">
                  <span>{log.src_ip} → {log.dest_ip}:{log.dest_port || "-"}</span>
                  <span>Proto: {log.proto} ({protoMap[log.proto_code] || "Unknown"})</span>
                  <span>Attack: {log.attack_type}</span>
                  <span>Timestamp: {log.timestamp}</span>
                  <span>Country: {log.country || "-"}</span>
                </div>
                <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${getAnomalyColor(log.anomaly || 0)}`}>
                  {(log.anomaly || 0).toFixed(2)}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
