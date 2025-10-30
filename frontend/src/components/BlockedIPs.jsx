import React, { useState, useEffect } from "react";
import axios from "axios";

const BlockedIPs = () => {
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [newIP, setNewIP] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(5); // Number of IPs per page
  const [totalItems, setTotalItems] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchBlockedIPs();
    const interval = setInterval(fetchBlockedIPs, 10000);
    return () => clearInterval(interval);
  }, [currentPage]);

  const fetchBlockedIPs = async () => {
    try {
      const response = await axios.get(
        `http://34.222.107.115:8000/api/blocked_ips?page=${currentPage}&per_page=${itemsPerPage}`
      );
      setBlockedIPs(response.data.blocked_ips);
      setTotalItems(response.data.total_items);
      setError("");
    } catch (error) {
      console.error("Error fetching blocked IPs:", error);
      setError("Failed to fetch blocked IPs. Please try again.");
    }
  };

  const handleUnblock = async (ip) => {
    try {
      await axios.post("http://34.222.107.115:8000/api/unblock_ip", { ip });
      fetchBlockedIPs();
      setError("");
    } catch (error) {
      console.error("Error unblocking IP:", error);
      setError(`Failed to unblock IP ${ip}. Please try again.`);
    }
  };

  const handleManualBlock = async (e) => {
    e.preventDefault();
    // Basic IP validation (IPv4)
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipRegex.test(newIP)) {
      setError("Please enter a valid IPv4 address (e.g., 192.168.1.100)");
      return;
    }
    try {
      await axios.post("http://34.222.107.115:8000/api/block_ip", { ip: newIP });
      setNewIP("");
      fetchBlockedIPs();
      setError("");
    } catch (error) {
      console.error("Error blocking IP:", error);
      setError(`Failed to block IP ${newIP}. Please try again.`);
    }
  };

  // Pagination calculations
  const totalPages = Math.ceil(totalItems / itemsPerPage);
  const pageNumbers = [];
  for (let i = 1; i <= totalPages; i++) {
    pageNumbers.push(i);
  }

  const handlePageChange = (page) => {
    if (page >= 1 && page <= totalPages) {
      setCurrentPage(page);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold text-gray-900 mb-8">
        Blocked IPs Management
      </h1>
      {/* Error Message */}
      {error && (
        <div className="mb-4 p-4 bg-red-100 text-red-700 rounded-md">
          {error}
        </div>
      )}
      {/* Manual Block Form */}
      <div className="bg-white p-6 rounded-lg shadow-md mb-6">
        <h3 className="text-xl font-semibold mb-4">Block New IP</h3>
        <form onSubmit={handleManualBlock} className="flex gap-4">
          <input
            type="text"
            placeholder="IP Address (e.g., 192.168.1.100)"
            value={newIP}
            onChange={(e) => setNewIP(e.target.value)}
            className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
            required
          />
          <button
            type="submit"
            className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700"
          >
            Block IP
          </button>
        </form>
      </div>
      {/* Blocked IPs Table */}
      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                IP Address
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Action
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {Array.isArray(blockedIPs) && blockedIPs.length > 0 ? (
              blockedIPs.map((ip, index) => (
                <tr key={index} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                    {ip}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-right">
                    <button
                      onClick={() => handleUnblock(ip)} // Fixed: use ip directly
                      className="text-green-600 hover:text-green-900"
                    >
                      Unblock
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="2" className="px-6 py-4 text-center text-sm text-gray-500">
                  No blocked IPs
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div className="mt-4 flex justify-between items-center">
          <div className="text-sm text-gray-700">
            Showing {blockedIPs.length} of {totalItems} IPs
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => handlePageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="px-3 py-1 bg-gray-200 text-gray-700 rounded-md disabled:opacity-50 hover:bg-gray-300"
            >
              Previous
            </button>
            {pageNumbers.map((page) => (
              <button
                key={page}
                onClick={() => handlePageChange(page)}
                className={`px-3 py-1 rounded-md ${
                  currentPage === page
                    ? "bg-blue-500 text-white"
                    : "bg-gray-200 text-gray-700 hover:bg-gray-300"
                }`}
              >
                {page}
              </button>
            ))}
            <button
              onClick={() => handlePageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="px-3 py-1 bg-gray-200 text-gray-700 rounded-md disabled:opacity-50 hover:bg-gray-300"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default BlockedIPs;