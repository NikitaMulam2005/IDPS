import React, { useState, useEffect } from "react";
import axios from "axios";

const SuricataDashboard = () => {
  const [suricataStatus, setSuricataStatus] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [statistics, setStatistics] = useState({});
  const [loading, setLoading] = useState(false);
  const [selectedInterface, setSelectedInterface] = useState("any");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [isStatsCollapsed, setIsStatsCollapsed] = useState(false);
  const BASE_URL = "http://34.222.107.115:8000/api";

  useEffect(() => {
    fetchSuricataData();
    const interval = setInterval(fetchSuricataData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchSuricataData = async () => {
    try {
      const statusRes = await axios.get(`${BASE_URL}/vps/status`);
      const suricataStatusData = statusRes.data.suricata_status || {};
      console.log("Suricata Status:", suricataStatusData);
      setSuricataStatus(suricataStatusData);

      const alertsRes = await axios.get(`${BASE_URL}/suricata/alerts`);
      const alertsData = alertsRes.data.alerts || [];
      console.log("Alerts Data:", alertsData);
      setAlerts(alertsData);

      const statsRes = await axios.get(`${BASE_URL}/suricata/statistics`);
      const statisticsData = statsRes.data.statistics || {};
      console.log("Statistics Data:", statisticsData);
      setStatistics(statisticsData);
    } catch (error) {
      console.error("Error fetching Suricata data:", error.response?.data || error.message);
    }
  };

  const handleStartSuricata = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${BASE_URL}/suricata/start`, {
        interface: selectedInterface,
      });
      if (response.data.status === "success") {
        alert("Suricata started successfully!");
        fetchSuricataData();
      } else {
        alert(`Failed to start Suricata: ${response.data.message}`);
      }
    } catch (error) {
      console.error("Error starting Suricata:", error.response?.data || error.message);
      alert(`Error starting Suricata: ${error.message}`);
    }
    setLoading(false);
  };

  const handleStopSuricata = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${BASE_URL}/suricata/stop`);
      if (response.data.status === "success") {
        alert("Suricata stopped successfully!");
        fetchSuricataData();
      } else {
        alert(`Failed to stop Suricata: ${response.data.message}`);
      }
    } catch (error) {
      console.error("Error stopping Suricata:", error.response?.data || error.message);
      alert(`Error stopping Suricata: ${error.message}`);
    }
    setLoading(false);
  };

  const handleUpdateRules = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${BASE_URL}/suricata/rules/update`);
      if (response.data.status === "success") {
        alert("Suricata rules updated successfully!");
      } else {
        alert(`Rules update result: ${response.data.message}`);
      }
    } catch (error) {
      console.error("Error updating rules:", error.response?.data || error.message);
      alert(`Error updating rules: ${error.message}`);
    }
    setLoading(false);
  };

  const getSeverityLabel = (severity) => {
    switch (severity) {
      case 1:
        return "Critical";
      case 2:
        return "High";
      case 3:
        return "Medium";
      case 4:
        return "Low";
      default:
        return "Info";
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 1:
        return "bg-red-100 text-red-700 border-red-300";
      case 2:
        return "bg-orange-100 text-orange-700 border-orange-300";
      case 3:
        return "bg-yellow-100 text-yellow-700 border-yellow-300";
      case 4:
        return "bg-blue-100 text-blue-700 border-blue-300";
      default:
        return "bg-gray-100 text-gray-700 border-gray-300";
    }
  };

  // Category-based color mapping for SIDs and category tags
  const getCategoryColor = (category) => {
    const colors = {
      "Potentially Bad Traffic": "bg-purple-100 text-purple-700 border-purple-300",
      "Policy Violation": "bg-teal-100 text-teal-700 border-teal-300",
      "Malware": "bg-pink-100 text-pink-700 border-pink-300",
      "Attempted Information Leak": "bg-indigo-100 text-indigo-700 border-indigo-300",
    };
    return colors[category] || "bg-gray-100 text-gray-700 border-gray-300";
  };

  // Get SID color based on the category of the first matching alert
  const getSidColor = (signature) => {
    const matchingAlert = alerts.find((alert) => alert.attack_type === signature);
    return matchingAlert ? getCategoryColor(matchingAlert.category) : "bg-gray-100 text-gray-700 border-gray-300";
  };

  // Filter alerts based on severity and category
  const filteredAlerts = alerts.filter(
    (alert) =>
      (severityFilter === "all" || alert.severity === parseInt(severityFilter)) &&
      (categoryFilter === "all" || alert.category === categoryFilter)
  );

  // Count-up animation component (runs only on initial render)
  const CountUp = ({ end, duration = 500 }) => {
    const [count, setCount] = useState(0);
    useEffect(() => {
      let startTime = null;
      const animate = (timestamp) => {
        if (!startTime) startTime = timestamp;
        const progress = timestamp - startTime;
        const increment = Math.min(end, Math.floor((progress / duration) * end));
        setCount(increment);
        if (progress < duration) requestAnimationFrame(animate);
      };
      requestAnimationFrame(animate);
    }, [end, duration]);
    return <span>{count}</span>;
  };

  return (
    <div className="p-8 max-w-7xl mx-auto font-sans">
      {/* Header */}
      <div className="mb-10">
        <h1 className="text-3xl font-bold text-gray-900 mb-6">
          Suricata Network IDS Dashboard
        </h1>

        {/* Status Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-white p-5 rounded-lg shadow-sm">
            <h3 className="text-sm font-medium text-gray-500">Status</h3>
            <p
              className={`text-xl font-semibold ${suricataStatus.running ? "text-green-600" : "text-red-600"}`}
            >
              <span
                className={`inline-block w-2 h-2 rounded-full mr-2 ${suricataStatus.running ? "bg-green-500" : "bg-red-500"}`}
              ></span>
              {suricataStatus.running ? "Running" : "Stopped"}
            </p>
            {suricataStatus.simulation_mode && (
              <p className="text-sm text-yellow-600 mt-1">Simulation Mode</p>
            )}
          </div>

          <div className="bg-white p-5 rounded-lg shadow-sm">
            <h3 className="text-sm font-medium text-gray-500">Installation</h3>
            <p
              className={`text-lg font-semibold ${suricataStatus.suricata_installed ? "text-green-600" : "text-yellow-600"}`}
            >
              <span
                className={`inline-block w-2 h-2 rounded-full mr-2 ${suricataStatus.suricata_installed ? "bg-green-500" : "bg-yellow-500"}`}
              ></span>
              {suricataStatus.suricata_installed ? "Installed" : "Simulation"}
            </p>
          </div>

          <div className="bg-white p-5 rounded-lg shadow-sm">
            <h3 className="text-sm font-medium text-gray-500">Total Alerts</h3>
            <p className="text-xl font-semibold text-blue-600">
              <CountUp end={statistics.total_alerts || 0} />
            </p>
            <p className="text-sm text-gray-500 mt-1">
              {suricataStatus.alerts_in_buffer || 0} in buffer
            </p>
          </div>

          <div className="bg-white p-5 rounded-lg shadow-sm">
            <h3 className="text-sm font-medium text-gray-500">Log File</h3>
            <p className="text-sm text-gray-700">
              <span
                className={`inline-block w-2 h-2 rounded-full mr-2 ${suricataStatus.eve_log_path ? "bg-blue-500" : "bg-red-500"}`}
              ></span>
              {suricataStatus.eve_log_path ? "Configured" : "Not Set"}
            </p>
          </div>
        </div>

        {/* Control Panel */}
        <div className="bg-white p-6 rounded-lg shadow-sm mb-8">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">
            Control Panel
          </h3>
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex space-x-3">
              {!suricataStatus.running ? (
                <button
                  onClick={handleStartSuricata}
                  disabled={loading}
                  className="px-4 py-2 bg-green-600 text-white rounded-md text-sm hover:bg-green-700 disabled:opacity-50 transition-colors"
                >
                  {loading ? "Starting..." : "Start Suricata"}
                </button>
              ) : (
                <button
                  onClick={handleStopSuricata}
                  disabled={loading}
                  className="px-4 py-2 bg-red-600 text-white rounded-md text-sm hover:bg-red-700 disabled:opacity-50 transition-colors"
                >
                  {loading ? "Stopping..." : "Stop Suricata"}
                </button>
              )}
              <button
                onClick={handleUpdateRules}
                disabled={loading}
                className="px-4 py-2 bg-blue-600 text-white rounded-md text-sm hover:bg-blue-700 disabled:opacity-50 transition-colors"
              >
                {loading ? "Updating..." : "Update Rules"}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Statistics and Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Alert Statistics */}
        <div className="bg-white p-6 rounded-lg shadow-sm">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-semibold text-gray-900">
              Alert Statistics
            </h3>
            <button
              onClick={() => setIsStatsCollapsed(!isStatsCollapsed)}
              className="text-blue-600 hover:text-blue-800"
            >
              <svg
                className={`w-5 h-5 transition-transform duration-200 ${isStatsCollapsed ? "rotate-180" : ""}`}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M19 9l-7 7-7-7"
                />
              </svg>
            </button>
          </div>
          <div
            className={`transition-all duration-300 ${isStatsCollapsed ? "h-0 overflow-hidden" : "h-auto"}`}
          >
            {/* Alerts by Category */}
            {statistics.alerts_by_category &&
              Object.keys(statistics.alerts_by_category).length > 0 && (
                <div className="mb-6">
                  <h4 className="text-md font-medium text-gray-700 mb-3">
                    By Category
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(statistics.alerts_by_category).map(
                      ([category, count]) => (
                        <button
                          key={category}
                          onClick={() => setCategoryFilter(category === categoryFilter ? "all" : category)}
                          className={`px-3 py-1 rounded-full text-sm font-medium transition-colors ${getCategoryColor(category)} ${
                            categoryFilter === category ? "ring-2 ring-blue-300" : "hover:bg-opacity-80"
                          }`}
                        >
                          {category} (<CountUp end={count} duration={500} />)
                        </button>
                      )
                    )}
                  </div>
                </div>
              )}

            {/* Top Signatures */}
            {statistics.top_signatures &&
              statistics.top_signatures.length > 0 && (
                <div>
                  <h4 className="text-md font-medium text-gray-700 mb-3">
                    Top Signatures
                  </h4>
                  <div className="space-y-3">
                    {statistics.top_signatures.slice(0, 5).map((sig, index) => {
                      const sid = alerts.find((a) => a.attack_type === sig.signature)?.signature_id || "N/A";
                      return (
                        <div
                          key={index}
                          onClick={() =>
                            setCategoryFilter(
                              alerts.find((a) => a.attack_type === sig.signature)?.category || "all"
                            )
                          }
                          className="p-3 bg-gray-50 rounded-md cursor-pointer hover:bg-gray-100 transition-colors"
                        >
                          <div className="flex justify-between items-center">
                            <span className="text-sm font-medium text-gray-800 truncate">
                              {sig.signature}
                            </span>
                            <span className="text-sm text-gray-600">
                              <CountUp end={sig.count} duration={500} />
                            </span>
                          </div>
                          <span
                            className={`inline-block mt-1 px-2 py-0.5 rounded-full text-xs font-medium ${getSidColor(
                              sig.signature
                            )}`}
                          >
                            SID: {sid}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="bg-white p-6 rounded-lg shadow-sm">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">
            Recent Alerts
          </h3>
          <div className="mb-4 flex flex-wrap gap-4">
            <div>
              <label
                htmlFor="severityFilter"
                className="text-sm font-medium text-gray-700 mr-2"
              >
                Severity:
              </label>
              <select
                id="severityFilter"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="p-2 border rounded-md text-sm"
              >
                <option value="all">All</option>
                <option value="1">Critical</option>
                <option value="2">High</option>
                <option value="3">Medium</option>
                <option value="4">Low</option>
              </select>
            </div>
            <div>
              <label
                htmlFor="categoryFilter"
                className="text-sm font-medium text-gray-700 mr-2"
              >
                Category:
              </label>
              <select
                id="categoryFilter"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="p-2 border rounded-md text-sm"
              >
                <option value="all">All</option>
                {statistics.alerts_by_category &&
                  Object.keys(statistics.alerts_by_category).map((category) => (
                    <option key={category} value={category}>
                      {category}
                    </option>
                  ))}
              </select>
            </div>
          </div>
          <div className="space-y-4 max-h-96 overflow-y-auto">
            {filteredAlerts.length > 0 ? (
              filteredAlerts.slice(0, 10).map((alert, index) => (
                <div
                  key={index}
                  className={`border-l-4 ${getSeverityColor(
                    alert.severity
                  )} bg-white p-4 rounded-r-md shadow-sm hover:shadow-md transition-shadow`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(
                        alert.severity
                      )}`}
                    >
                      {getSeverityLabel(alert.severity)}
                    </span>
                    <span className="text-xs text-gray-500">
                      {new Date(alert.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-gray-900 mb-2">
                    {alert.attack_type || "Unknown Alert"}
                  </h4>
                  <div className="text-xs text-gray-600 space-y-1">
                    <div>
                      <strong>Source:</strong> {alert.src_ip}:{alert.src_port} →{" "}
                      {alert.dest_ip}:{alert.dest_port}
                    </div>
                    <div>
                      <strong>Protocol:</strong> {alert.proto} |{" "}
                      <strong>Category:</strong> {alert.category || "N/A"} |{" "}
                      <strong>SID:</strong> {alert.signature_id}
                    </div>
                    {alert.anomaly !== null && alert.anomaly !== undefined && (
                      <div>
                        <strong>Anomaly Score:</strong>{" "}
                        {(alert.anomaly * 100).toFixed(0)}%
                      </div>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                {suricataStatus.running
                  ? "No alerts match the selected filters."
                  : "Start Suricata to begin monitoring for alerts."}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Installation Guide */}
      {!suricataStatus.suricata_installed && (
        <div className="mt-8 bg-yellow-50 border border-yellow-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-yellow-800 mb-4">
            Suricata Installation Guide
          </h3>
          <div className="text-sm text-yellow-700 space-y-2">
            <p>
              <strong>Windows:</strong>
            </p>
            <ul className="list-disc list-inside ml-4 space-y-1">
              <li>
                Download Suricata from:{" "}
                <a
                  href="https://suricata-ids.org/download/"
                  className="text-blue-600 underline"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  https://suricata-ids.org/download/
                </a>
              </li>
              <li>Install to C:\Program Files\Suricata\ or C:\suricata\</li>
              <li>Restart the AI-IDPS system after installation</li>
            </ul>
            <p className="mt-4">
              <strong>Linux:</strong>
            </p>
            <ul className="list-disc list-inside ml-4 space-y-1">
              <li>
                <code className="bg-gray-200 px-2 py-1 rounded">
                  sudo apt-get update && sudo apt-get install suricata
                </code>
              </li>
              <li>
                <code className="bg-gray-200 px-2 py-1 rounded">
                  sudo systemctl enable suricata
                </code>
              </li>
            </ul>
            <p className="mt-4 text-yellow-600">
              <strong>Note:</strong> Currently running in simulation mode with
              sample alerts for demonstration.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default SuricataDashboard;