import { useState } from "react";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import { LoginForm } from "./components/auth/LoginForm";
import { Sidebar, Header } from "./components/layout/Navigation";
import { DashboardOverview } from "./components/dashboard/DashboardOverview";

const AppContent = () => {
  const { state, login, logout } = useAuth();
  const [activeSection, setActiveSection] = useState("dashboard");

  // Mock data for dashboard
  const mockMetrics = {
    totalUsers: 1247,
    activeUsers: 89,
    policiesEnforced: 156,
    securityScore: 87,
    threatLevel: "low" as const,
  };

  const mockRecentEvents = [
    {
      id: "1",
      type: "login" as const,
      message: "Successful login from new device",
      timestamp: "2 minutes ago",
      severity: "medium" as const,
      user: "john.doe@company.com",
      location: "New York, US",
    },
    {
      id: "2",
      type: "policy_violation" as const,
      message: "Failed policy check: Unauthorized file access attempt",
      timestamp: "5 minutes ago",
      severity: "high" as const,
      user: "jane.smith@company.com",
      location: "London, UK",
    },
    {
      id: "3",
      type: "network_anomaly" as const,
      message: "Unusual network traffic pattern detected",
      timestamp: "12 minutes ago",
      severity: "medium" as const,
      location: "Data Center 1",
    },
    {
      id: "4",
      type: "access_denied" as const,
      message: "Access denied: Insufficient privileges",
      timestamp: "18 minutes ago",
      severity: "low" as const,
      user: "bob.wilson@company.com",
    },
  ];

  const handleLogin = async (data: {
    email: string;
    password: string;
    mfaCode?: string;
  }) => {
    await login(data.email, data.password, data.mfaCode);
  };

  const renderContent = () => {
    switch (activeSection) {
      case "dashboard":
        return (
          <DashboardOverview
            metrics={mockMetrics}
            recentEvents={mockRecentEvents}
          />
        );
      case "users":
        return (
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">User Management</h3>
            <p className="text-gray-600">
              User management interface coming soon...
            </p>
          </div>
        );
      case "network":
        return (
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Network Security</h3>
            <p className="text-gray-600">
              Network monitoring interface coming soon...
            </p>
          </div>
        );
      case "policies":
        return (
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Security Policies</h3>
            <p className="text-gray-600">
              Policy management interface coming soon...
            </p>
          </div>
        );
      case "security":
        return (
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Security Center</h3>
            <p className="text-gray-600">
              Security analysis interface coming soon...
            </p>
          </div>
        );
      case "settings":
        return (
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Settings</h3>
            <p className="text-gray-600">
              System settings interface coming soon...
            </p>
          </div>
        );
      default:
        return (
          <DashboardOverview
            metrics={mockMetrics}
            recentEvents={mockRecentEvents}
          />
        );
    }
  };

  const getSectionTitle = () => {
    switch (activeSection) {
      case "dashboard":
        return "Security Dashboard";
      case "users":
        return "User Management";
      case "network":
        return "Network Security";
      case "policies":
        return "Security Policies";
      case "security":
        return "Security Center";
      case "settings":
        return "Settings";
      default:
        return "Dashboard";
    }
  };

  if (!state.user?.isAuthenticated) {
    return (
      <LoginForm
        onLogin={handleLogin}
        loading={state.loading}
        requireMFA={state.requireMFA}
        error={state.error || undefined}
      />
    );
  }

  return (
    <div className="h-screen flex">
      <Sidebar
        activeSection={activeSection}
        onSectionChange={setActiveSection}
        onLogout={logout}
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title={getSectionTitle()} user={state.user} />
        <main className="flex-1 overflow-auto bg-gray-50 p-6">
          {renderContent()}
        </main>
      </div>
    </div>
  );
};

function App() {
  return (
    <AuthProvider>
      <div className="min-h-screen bg-gray-50">
        <AppContent />
      </div>
    </AuthProvider>
  );
}

export default App;
