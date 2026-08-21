import React, { useState } from 'react';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';

export default function App() {
  const [user, setUser] = useState({ username: 'analyst_admin', role: 'SOC Tier 2' });
  const [isLoggedIn, setIsLoggedIn] = useState(true);

  if (!isLoggedIn) {
    return (
      <Login 
        onLogin={(userData) => {
          setUser(userData);
          setIsLoggedIn(true);
        }} 
      />
    );
  }

  return (
    <Dashboard 
      user={user} 
      onLogout={() => setIsLoggedIn(false)} 
    />
  );
}
