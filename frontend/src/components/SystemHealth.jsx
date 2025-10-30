import React, { useState, useEffect } from "react";
import axios from "axios";

const SystemHealth = () => {
  const [health, setHealth] = useState({});

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const response = await axios.get(
          "http://34.222.107.115:8000/api/system_health"
        );
        setHealth(response.data);
      } catch (error) {
        console.error("Error fetching system health:", error);
      }
    };
    fetchHealth();
    const interval = setInterval(fetchHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (value, thresholds) => {
    if (value < thresholds.good) return "text-green-600";
    if (value < thresholds.warning) return "text-yellow-600";
    return "text-red-600";
  };

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h1 className="text-3xl font-bold text-gray-900 mb-8">System Health</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* CPU Usage */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700 mb-2">
            CPU Usage
          </h3>
          <p
            className={`text-3xl font-bold ${getStatusColor(health.cpu_usage, {
              good: 50,
              warning: 80,
            })}`}
          >
            {health.cpu_usage?.toFixed(1)}%
          </p>
          <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
            <div
              className="bg-blue-600 h-2 rounded-full"
              style={{ width: `${health.cpu_usage}%` }}
            ></div>
          </div>
        </div>
        {/* Memory Usage */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700 mb-2">
            Memory Usage
          </h3>
          <p
            className={`text-3xl font-bold ${getStatusColor(
              health.memory_usage,
              { good: 60, warning: 85 }
            )}`}
          >
            {health.memory_usage?.toFixed(1)}%
          </p>
          <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
            <div
              className="bg-green-600 h-2 rounded-full"
              style={{ width: `${health.memory_usage}%` }}
            ></div>
          </div>
        </div>
        {/* Alerts Per Minute */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700 mb-2">
            Alerts/Min
          </h3>
          <p className="text-3xl font-bold text-blue-600">
            {health.alerts_per_minute || 0}
          </p>
          <p className="text-sm text-gray-500 mt-2">Real-time rate</p>
        </div>
        {/* ML Model Status */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700 mb-2">ML Model</h3>
          <p className="text-3xl font-bold text-green-600">
            {(health.ml_model_accuracy * 100)?.toFixed(1)}%
          </p>
          <p className="text-sm text-gray-500 mt-2">Accuracy</p>
        </div>
        {/* Active Connections */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700 mb-2">
            Connections
          </h3>
          <p className="text-3xl font-bold text-purple-600">
            {health.active_connections || 0}
          </p>
          <p className="text-sm text-gray-500 mt-2">Active</p>
        </div>
        {/* System Uptime */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700 mb-2">Uptime</h3>
          <p className="text-2xl font-bold text-indigo-600">
            {health.uptime ? Math.floor(health.uptime / 3600) : 0}h
          </p>
          <p className="text-sm text-gray-500 mt-2">Hours running</p>
        </div>
      </div>
    </div>
  );
};

export default SystemHealth;
