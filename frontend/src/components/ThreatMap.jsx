import React, { useState, useEffect } from "react";
import axios from "axios";

const ThreatMap = () => {
  const [threatData, setThreatData] = useState({});
  const [selectedCountry, setSelectedCountry] = useState(null);

  useEffect(() => {
    fetchThreatData();
    const interval = setInterval(fetchThreatData, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchThreatData = async () => {
    try {
      const response = await axios.get(
        "http://localhost:5000/api/threat_trends"
      );
      setThreatData(response.data);
    } catch (error) {
      console.error("Error fetching threat data:", error);
    }
  };

  const getCountryThreatLevel = (count, maxCount) => {
    const percentage = (count / maxCount) * 100;
    if (percentage >= 80) return "bg-red-600";
    if (percentage >= 60) return "bg-orange-500";
    if (percentage >= 40) return "bg-yellow-500";
    if (percentage >= 20) return "bg-green-500";
    return "bg-gray-300";
  };

  const getCountryFlag = (countryCode) => {
    const flags = {
      US: "US",
      CN: "CN",
      RU: "RU",
      IN: "IN",
      BR: "BR",
      DE: "DE",
      FR: "FR",
      UK: "UK",
      JP: "JP",
      KR: "KR",
    };
    return flags[countryCode] || countryCode;
  };

  const maxCount = threatData.countries?.[0]?.count || 1;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Global Threat Map</h1>
        <p className="mt-2 text-gray-600">
          Real-time visualization of global security threats
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Map Visualization (Simplified) */}
        <div className="lg:col-span-2">
          <div className="bg-white rounded-lg shadow-md">
            <div className="p-6 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">
                Geographic Distribution
              </h3>
            </div>
            <div className="p-6">
              {/* Simplified World Map Representation */}
              <div className="bg-gray-100 rounded-lg p-8 min-h-96 relative">
                <div className="text-center text-gray-500 absolute inset-0 flex items-center justify-center">
                  <div>
                    <div className="text-4xl mb-4">
                      <span className="w-12 h-12 bg-blue-500 rounded-full flex items-center justify-center text-white font-bold">
                        G
                      </span>
                    </div>
                    <p className="text-lg font-medium">
                      Global Threat Activity
                    </p>
                    <p className="text-sm">Interactive map visualization</p>
                  </div>
                </div>

                {/* Country Threat Indicators */}
                <div className="absolute bottom-4 left-4 right-4">
                  <div className="flex justify-between items-center text-xs text-gray-600">
                    <span>Low Activity</span>
                    <div className="flex space-x-1">
                      <div className="w-4 h-2 bg-green-300 rounded"></div>
                      <div className="w-4 h-2 bg-yellow-400 rounded"></div>
                      <div className="w-4 h-2 bg-orange-500 rounded"></div>
                      <div className="w-4 h-2 bg-red-600 rounded"></div>
                    </div>
                    <span>High Activity</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Country Statistics */}
        <div className="bg-white rounded-lg shadow-md">
          <div className="p-6 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900">
              Threat by Country
            </h3>
          </div>
          <div className="p-6">
            <div className="space-y-4 max-h-96 overflow-y-auto">
              {threatData.countries && threatData.countries.length > 0 ? (
                threatData.countries.map((country, index) => (
                  <div
                    key={index}
                    className={`p-3 rounded-lg border cursor-pointer hover:bg-gray-50 transition-colors ${
                      selectedCountry === country.name
                        ? "border-blue-500 bg-blue-50"
                        : "border-gray-200"
                    }`}
                    onClick={() =>
                      setSelectedCountry(
                        selectedCountry === country.name ? null : country.name
                      )
                    }
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-3">
                        <span className="px-2 py-1 bg-gray-100 rounded text-sm font-mono">
                          {getCountryFlag(country.name)}
                        </span>
                        <span className="font-medium text-gray-900">
                          {country.name}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <div
                          className={`w-3 h-3 rounded-full ${getCountryThreatLevel(
                            country.count,
                            maxCount
                          )}`}
                        ></div>
                        <span className="font-bold text-gray-900">
                          {country.count}
                        </span>
                      </div>
                    </div>

                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${getCountryThreatLevel(
                          country.count,
                          maxCount
                        )}`}
                        style={{
                          width: `${(country.count / maxCount) * 100}%`,
                        }}
                      ></div>
                    </div>

                    {selectedCountry === country.name && (
                      <div className="mt-3 p-3 bg-white rounded border">
                        <h4 className="font-medium text-sm text-gray-700 mb-2">
                          Threat Details
                        </h4>
                        <div className="text-xs text-gray-600 space-y-1">
                          <div className="flex justify-between">
                            <span>Total Threats:</span>
                            <span className="font-medium">{country.count}</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Threat Level:</span>
                            <span
                              className={`font-medium ${
                                country.count / maxCount >= 0.8
                                  ? "text-red-600"
                                  : country.count / maxCount >= 0.6
                                  ? "text-orange-500"
                                  : country.count / maxCount >= 0.4
                                  ? "text-yellow-500"
                                  : "text-green-500"
                              }`}
                            >
                              {country.count / maxCount >= 0.8
                                ? "Critical"
                                : country.count / maxCount >= 0.6
                                ? "High"
                                : country.count / maxCount >= 0.4
                                ? "Medium"
                                : "Low"}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span>Percentage:</span>
                            <span className="font-medium">
                              {((country.count / maxCount) * 100).toFixed(1)}%
                            </span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-center text-gray-500 py-8">
                  <div className="w-8 h-8 bg-gray-400 rounded-full mx-auto mb-2 flex items-center justify-center">
                    <span className="text-white font-bold text-sm">?</span>
                  </div>
                  <p>No geographic data available</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Threat Statistics */}
      <div className="mt-8 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-md text-center">
          <div className="w-12 h-12 bg-blue-500 rounded-full mx-auto mb-2 flex items-center justify-center">
            <span className="text-white font-bold">W</span>
          </div>
          <h3 className="text-lg font-semibold text-gray-900">
            {threatData.countries?.length || 0}
          </h3>
          <p className="text-sm text-gray-600">Active Countries</p>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md text-center">
          <div className="w-12 h-12 bg-red-500 rounded-full mx-auto mb-2 flex items-center justify-center">
            <span className="text-white font-bold">!</span>
          </div>
          <h3 className="text-lg font-semibold text-red-600">
            {threatData.countries?.reduce(
              (sum, country) => sum + country.count,
              0
            ) || 0}
          </h3>
          <p className="text-sm text-gray-600">Total Threats</p>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md text-center">
          <div className="w-12 h-12 bg-orange-500 rounded-full mx-auto mb-2 flex items-center justify-center">
            <span className="text-white font-bold">H</span>
          </div>
          <h3 className="text-lg font-semibold text-orange-600">
            {threatData.countries?.filter((c) => c.count / maxCount >= 0.6)
              .length || 0}
          </h3>
          <p className="text-sm text-gray-600">High Risk Countries</p>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md text-center">
          <div className="w-12 h-12 bg-green-500 rounded-full mx-auto mb-2 flex items-center justify-center">
            <span className="text-white font-bold">T</span>
          </div>
          <h3 className="text-lg font-semibold text-green-600">
            {threatData.alert_types?.length || 0}
          </h3>
          <p className="text-sm text-gray-600">Threat Types</p>
        </div>
      </div>
    </div>
  );
};

export default ThreatMap;
