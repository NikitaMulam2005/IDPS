import React from "react";
import { BrowserRouter as Router, Routes, Route, Link } from "react-router-dom";
import Dashboard from "./components/Dashboard";
import AlertTable from "./components/AlertTable";
import BlockedIPs from "./components/BlockedIPs";
import SystemHealth from "./components/SystemHealth";
import Reports from "./components/Reports";
import SuricataDashboard from "./components/SuricataDashboard";
import RealTimeRiskMap from "./components/RealTimeRiskMap";

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-100">
        {/* Navigation */}
        <nav className="bg-blue-900 text-white shadow-lg">
          <div className="max-w-7xl mx-auto px-4">
            <div className="flex justify-between h-16">
              <div className="flex items-center">
                <h1 className="text-xl font-bold">🛡️ Enterprise AI-IDPS</h1>
              </div>
              <div className="flex items-center space-x-4">
                <Link to="/" className="hover:bg-blue-800 px-3 py-2 rounded">
                  Dashboard
                </Link>
                <Link
                  to="/alerts"
                  className="hover:bg-blue-800 px-3 py-2 rounded"
                >
                  Alerts
                </Link>
                <Link
                  to="/suricata"
                  className="hover:bg-blue-800 px-3 py-2 rounded"
                >
                  Suricata IDS
                </Link>
                <Link
                  to="/risk-map"
                  className="hover:bg-blue-800 px-3 py-2 rounded"
                >
                  Risk Map
                </Link>
                <Link
                  to="/blocked"
                  className="hover:bg-blue-800 px-3 py-2 rounded"
                >
                  Blocked IPs
                </Link>
                <Link
                  to="/health"
                  className="hover:bg-blue-800 px-3 py-2 rounded"
                >
                  Health
                </Link>
                <Link
                  to="/reports"
                  className="hover:bg-blue-800 px-3 py-2 rounded"
                >
                  Reports
                </Link>
              </div>
            </div>
          </div>
        </nav>
        {/* Routes */}
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<AlertTable />} />
          <Route path="/suricata" element={<SuricataDashboard />} />
          <Route path="/risk-map" element={<RealTimeRiskMap />} />
          <Route path="/blocked" element={<BlockedIPs />} />
          <Route path="/health" element={<SystemHealth />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
