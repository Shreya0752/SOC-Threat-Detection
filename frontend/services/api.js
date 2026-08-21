const API_BASE_URL = window.location.origin.includes("5000") 
  ? window.location.origin 
  : "http://127.0.0.1:5000";

export const login = async (username, password) => {
  const res = await fetch(`${API_BASE_URL}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ username, password })
  });
  
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || "Invalid username or password");
  }
  return data;
};

export const logout = async () => {
  try {
    await fetch(`${API_BASE_URL}/logout`, {
      method: "POST",
      credentials: "include"
    });
  } catch (error) {
    console.error("Logout error:", error);
  }
};

export const fetchCurrentUser = async () => {
  try {
    const res = await fetch(`${API_BASE_URL}/me`, {
      credentials: "include"
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.user;
  } catch (error) {
    return null;
  }
};

export const fetchEvents = async (params = {}) => {
  try {
    const query = new URLSearchParams();
    if (params.severity && params.severity !== "All") query.append("severity", params.severity);
    if (params.date) query.append("date", params.date);
    if (params.eventType && params.eventType !== "All") query.append("event_type", params.eventType);
    if (params.ipAddress) query.append("ip_address", params.ipAddress);
    if (params.search) query.append("search", params.search);
    if (params.page) query.append("page", params.page);
    if (params.limit) query.append("limit", params.limit || 50);

    const res = await fetch(`${API_BASE_URL}/events?${query.toString()}`, {
      credentials: "include"
    });
    if (res.status === 401) return { total: 0, events: [], unauthorized: true };
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error("Error fetching events:", error);
    return { total: 0, events: [], error: error.message };
  }
};

export const fetchStats = async () => {
  try {
    const res = await fetch(`${API_BASE_URL}/stats`, {
      credentials: "include"
    });
    if (res.status === 401) return { unauthorized: true };
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error("Error fetching stats:", error);
    return {
      total_events: 0,
      critical_events: 0,
      high_events: 0,
      medium_events: 0,
      low_events: 0,
      vulnerabilities: 0,
      active_incidents: 0,
      malware_events: 0,
      mitre_mapped_events: 0,
      mitre_mapping_percentage: 0,
      error: error.message
    };
  }
};

export const fetchThreats = async () => {
  try {
    const res = await fetch(`${API_BASE_URL}/threats`, {
      credentials: "include"
    });
    if (res.status === 401) return [];
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error("Error fetching threats:", error);
    return [];
  }
};

// =========================================================
// MILESTONE 2 REST API SERVICES
// =========================================================

export const fetchPredictions = async (params = {}) => {
  try {
    const query = new URLSearchParams();
    if (params.page) query.append("page", params.page);
    if (params.limit) query.append("limit", params.limit || 25);
    if (params.prediction && params.prediction !== "All") query.append("prediction", params.prediction);
    if (params.threat_type && params.threat_type !== "All") query.append("threat_type", params.threat_type);
    if (params.severity && params.severity !== "All") query.append("severity", params.severity);
    if (params.search) query.append("search", params.search);

    const res = await fetch(`${API_BASE_URL}/predictions?${query.toString()}`, {
      credentials: "include"
    });
    if (res.status === 401) return { total: 0, predictions: [], unauthorized: true };
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error("Error fetching predictions:", error);
    return { total: 0, predictions: [], error: error.message };
  }
};

export const fetchPredictionByEventId = async (eventId) => {
  try {
    const res = await fetch(`${API_BASE_URL}/predictions/${encodeURIComponent(eventId)}`, {
      credentials: "include"
    });
    if (res.status === 401) return { unauthorized: true };
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error(`Error fetching prediction for ${eventId}:`, error);
    return null;
  }
};

export const fetchAnomalies = async (params = {}) => {
  try {
    const query = new URLSearchParams();
    if (params.page) query.append("page", params.page);
    if (params.limit) query.append("limit", params.limit || 25);

    const res = await fetch(`${API_BASE_URL}/anomalies?${query.toString()}`, {
      credentials: "include"
    });
    if (res.status === 401) return { total: 0, anomalies: [], unauthorized: true };
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error("Error fetching anomalies:", error);
    return { total: 0, anomalies: [], error: error.message };
  }
};

export const fetchModelPerformance = async () => {
  try {
    const res = await fetch(`${API_BASE_URL}/model-performance`, {
      credentials: "include"
    });
    if (res.status === 401) return { unauthorized: true };
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error("Error fetching model performance:", error);
    return { error: error.message };
  }
};

export const fetchThreatSummary = async () => {
  try {
    const res = await fetch(`${API_BASE_URL}/threat-summary`, {
      credentials: "include"
    });
    if (res.status === 401) return { unauthorized: true };
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error("Error fetching threat summary:", error);
    return { error: error.message };
  }
};

export const predictEvent = async (eventId) => {
  try {
    const res = await fetch(`${API_BASE_URL}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ event_id: eventId })
    });
    if (res.status === 401) return { unauthorized: true };
    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.error || `HTTP error! status: ${res.status}`);
    }
    return await res.json();
  } catch (error) {
    console.error(`Error predicting event ${eventId}:`, error);
    return { error: error.message };
  }
};

// Aliases for M2 requirement naming conventions
export const getPredictions = fetchPredictions;
export const getPrediction = fetchPredictionByEventId;
export const getAnomalies = fetchAnomalies;
export const getModelPerformance = fetchModelPerformance;
export const getThreatSummary = fetchThreatSummary;
