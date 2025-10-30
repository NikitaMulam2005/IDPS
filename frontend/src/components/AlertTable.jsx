import React, { useState, useEffect } from "react";
import axios from "axios";

const AlertTable = () => {
  const [alerts, setAlerts] = useState([]);
  const [pagination, setPagination] = useState({ total: 0, page: 1, per_page: 20, pages: 1 });
  const [currentPage, setCurrentPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const BASE_URL = "http://34.222.107.115:8000/api";

  useEffect(() => {
    fetchAlerts(currentPage);
  }, [currentPage]);
const fetchAlerts = async (page = 1) => {
  setLoading(true);
  try {
    const res = await axios.get(`${BASE_URL}/live_threats`, {
      params: { page, per_page: pagination.per_page },
    });
    const data = res.data || {};
    const fetchedAlerts = data.malicious_ips || []; // fallback to empty array
    const total = data.total || fetchedAlerts.length; // fallback if backend doesn't send total

    setAlerts(fetchedAlerts);
    setPagination((prev) => ({
      ...prev,
      total,
      page,
      pages: Math.ceil(total / prev.per_page) || 1,
    }));
  } catch (err) {
    console.error("Error fetching live threats:", err);
    setAlerts([]); // fallback to empty array on error
  } finally {
    setLoading(false);
  }
};

  const handlePageChange = (page) => {
    if (page >= 1 && page <= pagination.pages) {
      setCurrentPage(page);
    }
  };

  const getSeverityColor = (score) =>
    score === -1 ? "bg-red-100 text-red-800" : "bg-green-100 text-green-800";

  const renderPageNumbers = () => {
    const totalPages = pagination.pages;
    const pageNumbers = [];
    let start = Math.max(1, currentPage - 2);
    let end = Math.min(totalPages, start + 4);
    start = Math.max(1, end - 4);

    for (let i = start; i <= end; i++) {
      pageNumbers.push(
        <button
          key={i}
          onClick={() => handlePageChange(i)}
          className={`px-3 py-1 border rounded text-sm font-medium ${
            currentPage === i ? "bg-blue-500 text-white" : "bg-white text-gray-700 hover:bg-gray-100"
          }`}
        >
          {i}
        </button>
      );
    }
    return pageNumbers;
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <h1 className="text-3xl font-bold mb-2">Network Alerts</h1>
      <p className="text-gray-600 mb-4">Monitor source/destination activity and anomalies</p>

      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">
            Network Alerts ({pagination.total} total)
          </h3>
        </div>

        {loading ? (
          <div className="p-8 text-center">
            <div className="animate-spin h-8 w-8 border-b-2 border-blue-600 mx-auto rounded-full"></div>
            <p className="mt-2 text-gray-500">Loading alerts...</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {[
                    "Timestamp",
                    "Source IP",
                    "Destination IP",
                    "Destination Port",
                    "Protocol",
                    "Threat Type",
                    "Country",
                    "Count",
                    "Anomaly",
                  ].map((col) => (
                    <th
                      key={col}
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                    >
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {alerts.length > 0 ? (
                  alerts.map((alert, idx) => (
                    <tr key={alert.src_ip + alert.timestamp + idx} className="hover:bg-gray-50">
                      <td className="px-6 py-4 text-sm text-gray-900">{new Date(alert.timestamp).toLocaleString()}</td>
                      <td className="px-6 py-4 text-sm font-mono text-gray-900">{alert.src_ip}</td>
                      <td className="px-6 py-4 text-sm font-mono text-gray-900">{alert.dest_ip}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{alert.dest_port}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{alert.proto}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{alert.attack_type}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{alert.country}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{alert.count || 1}</td>
                      <td className="px-6 py-4">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(alert.anomaly_score)}`}>
                          {alert.anomaly_score === -1 ? "Blocked" : "Allowed"}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="9" className="px-6 py-4 text-center text-gray-500">
                      No alerts found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {pagination.pages > 1 && (
          <div className="px-6 py-3 flex justify-center space-x-2 border-t border-gray-200">
            <button
              onClick={() => handlePageChange(currentPage - 1)}
              disabled={currentPage <= 1}
              className="px-3 py-1 border rounded text-sm font-medium bg-white text-gray-700 hover:bg-gray-100 disabled:opacity-50"
            >
              Previous
            </button>
            {renderPageNumbers()}
            <button
              onClick={() => handlePageChange(currentPage + 1)}
              disabled={currentPage >= pagination.pages}
              className="px-3 py-1 border rounded text-sm font-medium bg-white text-gray-700 hover:bg-gray-100 disabled:opacity-50"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default AlertTable;
