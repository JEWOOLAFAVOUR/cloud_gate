import React from "react";
import {
  Shield,
  Users,
  Network,
  AlertTriangle,
  CheckCircle,
  XCircle,
  TrendingUp,
  Clock,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "../ui/Card";

interface MetricCardProps {
  title: string;
  value: string | number;
  description: string;
  icon: React.ReactNode;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  status?: "success" | "warning" | "error";
}

const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  description,
  icon,
  trend,
  status = "success",
}) => {
  const statusColors = {
    success: "text-green-600",
    warning: "text-yellow-600",
    error: "text-red-600",
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <div className={statusColors[status]}>{icon}</div>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        <p className="text-xs text-gray-600">{description}</p>
        {trend && (
          <div
            className={`flex items-center text-xs mt-2 ${
              trend.isPositive ? "text-green-600" : "text-red-600"
            }`}
          >
            <TrendingUp className="h-3 w-3 mr-1" />
            {trend.value}% from last month
          </div>
        )}
      </CardContent>
    </Card>
  );
};

interface SecurityEvent {
  id: string;
  type: "login" | "policy_violation" | "network_anomaly" | "access_denied";
  message: string;
  timestamp: string;
  severity: "low" | "medium" | "high";
  user?: string;
  location?: string;
}

interface DashboardOverviewProps {
  metrics: {
    totalUsers: number;
    activeUsers: number;
    policiesEnforced: number;
    securityScore: number;
    threatLevel: "low" | "medium" | "high";
  };
  recentEvents: SecurityEvent[];
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  metrics,
  recentEvents,
}) => {
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "high":
        return <XCircle className="h-4 w-4 text-red-500" />;
      case "medium":
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default:
        return <CheckCircle className="h-4 w-4 text-green-500" />;
    }
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case "high":
        return "text-red-600 bg-red-50 border-red-200";
      case "medium":
        return "text-yellow-600 bg-yellow-50 border-yellow-200";
      default:
        return "text-green-600 bg-green-50 border-green-200";
    }
  };

  return (
    <div className="space-y-6">
      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard
          title="Total Users"
          value={metrics.totalUsers}
          description="Registered in the system"
          icon={<Users className="h-4 w-4" />}
          trend={{ value: 12, isPositive: true }}
        />
        <MetricCard
          title="Active Users"
          value={metrics.activeUsers}
          description="Currently authenticated"
          icon={<CheckCircle className="h-4 w-4" />}
          trend={{ value: 8, isPositive: true }}
        />
        <MetricCard
          title="Policies Enforced"
          value={metrics.policiesEnforced}
          description="Security policies active"
          icon={<Shield className="h-4 w-4" />}
        />
        <MetricCard
          title="Security Score"
          value={`${metrics.securityScore}%`}
          description="Overall security rating"
          icon={<Network className="h-4 w-4" />}
          trend={{ value: 5, isPositive: true }}
          status={
            metrics.securityScore >= 80
              ? "success"
              : metrics.securityScore >= 60
              ? "warning"
              : "error"
          }
        />
      </div>

      {/* Threat Level and Recent Events */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Level */}
        <Card>
          <CardHeader>
            <CardTitle>Current Threat Level</CardTitle>
            <CardDescription>System-wide security assessment</CardDescription>
          </CardHeader>
          <CardContent>
            <div
              className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${getThreatLevelColor(
                metrics.threatLevel
              )}`}
            >
              {getSeverityIcon(metrics.threatLevel)}
              <span className="ml-2 capitalize">{metrics.threatLevel}</span>
            </div>
            <p className="text-sm text-gray-600 mt-3">
              Based on recent security events and policy violations
            </p>
          </CardContent>
        </Card>

        {/* Recent Security Events */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Recent Security Events</CardTitle>
            <CardDescription>
              Latest security activities and alerts
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {recentEvents.slice(0, 5).map((event) => (
                <div
                  key={event.id}
                  className="flex items-start gap-3 p-3 border border-gray-200 rounded-md"
                >
                  {getSeverityIcon(event.severity)}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium">{event.message}</p>
                    <div className="flex items-center gap-4 mt-1 text-xs text-gray-600">
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {event.timestamp}
                      </span>
                      {event.user && <span>User: {event.user}</span>}
                      {event.location && (
                        <span>Location: {event.location}</span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
