import express from "express";
import {
  authenticateToken,
  requirePermission,
  AuthenticatedRequest,
} from "../middleware/auth";
import { AppError, asyncHandler } from "../middleware/errorHandler";
import { getCosmosClient } from "../utils/azure";
import { logger } from "../utils/logger";

const router = express.Router();

// Security metrics and monitoring interfaces
interface SecurityEvent {
  id: string;
  type:
    | "login"
    | "logout"
    | "access_denied"
    | "policy_violation"
    | "suspicious_activity"
    | "mfa_challenge";
  severity: "low" | "medium" | "high" | "critical";
  userId?: string;
  userEmail?: string;
  sourceIP: string;
  userAgent?: string;
  deviceId?: string;
  location?: {
    country: string;
    city: string;
    coordinates: [number, number];
  };
  details: Record<string, any>;
  timestamp: Date;
  riskScore: number;
  resolved: boolean;
}

interface SecurityMetrics {
  totalUsers: number;
  activeUsers: number;
  totalPolicies: number;
  activePolicies: number;
  totalEvents: number;
  highRiskEvents: number;
  averageRiskScore: number;
  mfaAdoptionRate: number;
  deviceTrustLevel: number;
  networkSegments: number;
}

// Get security dashboard metrics
router.get(
  "/dashboard",
  authenticateToken,
  requirePermission("read:security"),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");

    // Calculate metrics
    const metrics = await calculateSecurityMetrics(database);

    res.json({
      success: true,
      data: {
        metrics,
        lastUpdated: new Date(),
      },
    });
  })
);

// Get security events
router.get(
  "/events",
  authenticateToken,
  requirePermission("read:security"),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const {
      page = 1,
      limit = 50,
      severity,
      type,
      startDate,
      endDate,
    } = req.query;

    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");

    await database.containers.createIfNotExists({
      id: "security_events",
      partitionKey: { paths: ["/type"] },
    });

    const container = database.container("security_events");

    let query = "SELECT * FROM c WHERE 1=1";
    const parameters: any[] = [];

    if (severity) {
      query += " AND c.severity = @severity";
      parameters.push({ name: "@severity", value: severity });
    }

    if (type) {
      query += " AND c.type = @type";
      parameters.push({ name: "@type", value: type });
    }

    if (startDate) {
      query += " AND c.timestamp >= @startDate";
      parameters.push({
        name: "@startDate",
        value: new Date(startDate as string),
      });
    }

    if (endDate) {
      query += " AND c.timestamp <= @endDate";
      parameters.push({ name: "@endDate", value: new Date(endDate as string) });
    }

    query += " ORDER BY c.timestamp DESC";

    const { resources: events } = await container.items
      .query({ query, parameters })
      .fetchAll();

    // Pagination
    const offset = ((page as number) - 1) * (limit as number);
    const paginatedEvents = events.slice(offset, offset + (limit as number));

    res.json({
      success: true,
      data: {
        events: paginatedEvents,
        total: events.length,
        page: page as number,
        limit: limit as number,
        totalPages: Math.ceil(events.length / (limit as number)),
      },
    });
  })
);

// Log security event
router.post(
  "/events",
  authenticateToken,
  requirePermission("create:security"),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const { type, severity, details, userId, userEmail } = req.body;

    if (!type || !severity) {
      throw new AppError("Event type and severity are required", 400);
    }

    const event: SecurityEvent = {
      id: require("uuid").v4(),
      type,
      severity,
      userId,
      userEmail,
      sourceIP: req.ip || "unknown",
      userAgent: req.get("User-Agent"),
      deviceId: req.get("X-Device-ID"),
      details: details || {},
      timestamp: new Date(),
      riskScore: calculateEventRiskScore(type, severity, details),
      resolved: false,
    };

    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("security_events");

    await container.items.create(event);

    logger.warn(
      `Security event logged: ${type} (${severity}) - ${userEmail || "Unknown user"}`
    );

    res.status(201).json({
      success: true,
      message: "Security event logged successfully",
      data: event,
    });
  })
);

// Get risk analysis
router.get(
  "/risk-analysis",
  authenticateToken,
  requirePermission("read:security"),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");

    // Get recent high-risk events
    const eventsContainer = database.container("security_events");
    const { resources: highRiskEvents } = await eventsContainer.items
      .query(
        `
        SELECT * FROM c 
        WHERE c.riskScore > 0.7 
        AND c.timestamp > DateTimeAdd("day", -7, GetCurrentDateTime())
        ORDER BY c.riskScore DESC, c.timestamp DESC
      `
      )
      .fetchAll();

    // Get users with high risk scores
    const usersContainer = database.container("users");
    const { resources: users } = await usersContainer.items
      .query("SELECT c.id, c.email, c.failedLoginAttempts, c.lastLogin FROM c")
      .fetchAll();

    const riskAnalysis = {
      highRiskEvents: highRiskEvents.slice(0, 10),
      riskTrends: await calculateRiskTrends(database),
      topRiskFactors: await getTopRiskFactors(database),
      recommendations: generateSecurityRecommendations(highRiskEvents, users),
    };

    res.json({
      success: true,
      data: riskAnalysis,
    });
  })
);

// Helper functions
async function calculateSecurityMetrics(
  database: any
): Promise<SecurityMetrics> {
  // Users metrics
  const usersContainer = database.container("users");
  const { resources: allUsers } = await usersContainer.items
    .query("SELECT * FROM c")
    .fetchAll();
  const activeUsers = allUsers.filter((user: any) => user.isActive);
  const mfaEnabledUsers = allUsers.filter((user: any) => user.mfaEnabled);

  // Policies metrics
  const policiesContainer = database.container("policies");
  const { resources: allPolicies } = await policiesContainer.items
    .query("SELECT * FROM c")
    .fetchAll();
  const activePolicies = allPolicies.filter((policy: any) => policy.isActive);

  // Events metrics
  const eventsContainer = database.container("security_events");
  const { resources: allEvents } = await eventsContainer.items
    .query("SELECT * FROM c")
    .fetchAll();
  const highRiskEvents = allEvents.filter(
    (event: any) => event.riskScore > 0.7
  );

  const totalRiskScore = allEvents.reduce(
    (sum: number, event: any) => sum + event.riskScore,
    0
  );
  const averageRiskScore =
    allEvents.length > 0 ? totalRiskScore / allEvents.length : 0;

  // Network metrics
  const networkContainer = database.container("network_segments");
  const { resources: networkSegments } = await networkContainer.items
    .query("SELECT * FROM c")
    .fetchAll();

  // Device trust metrics
  const devicesContainer = database.container("devices");
  const { resources: devices } = await devicesContainer.items
    .query("SELECT * FROM c")
    .fetchAll();
  const trustedDevices = devices.filter(
    (device: any) => device.riskScore < 0.3
  );
  const deviceTrustLevel =
    devices.length > 0 ? trustedDevices.length / devices.length : 1;

  return {
    totalUsers: allUsers.length,
    activeUsers: activeUsers.length,
    totalPolicies: allPolicies.length,
    activePolicies: activePolicies.length,
    totalEvents: allEvents.length,
    highRiskEvents: highRiskEvents.length,
    averageRiskScore,
    mfaAdoptionRate:
      allUsers.length > 0 ? mfaEnabledUsers.length / allUsers.length : 0,
    deviceTrustLevel,
    networkSegments: networkSegments.length,
  };
}

async function calculateRiskTrends(database: any) {
  const eventsContainer = database.container("security_events");

  // Get events from last 30 days
  const { resources: recentEvents } = await eventsContainer.items
    .query(
      `
      SELECT * FROM c 
      WHERE c.timestamp > DateTimeAdd("day", -30, GetCurrentDateTime())
      ORDER BY c.timestamp
    `
    )
    .fetchAll();

  // Group by day and calculate average risk score
  const trends: Array<{
    date: string;
    averageRiskScore: number;
    eventCount: number;
  }> = [];
  const eventsByDay = new Map();

  recentEvents.forEach((event: any) => {
    const day = new Date(event.timestamp).toDateString();
    if (!eventsByDay.has(day)) {
      eventsByDay.set(day, []);
    }
    eventsByDay.get(day).push(event);
  });

  eventsByDay.forEach((events, day) => {
    const totalRisk = events.reduce(
      (sum: number, event: any) => sum + event.riskScore,
      0
    );
    const avgRisk = events.length > 0 ? totalRisk / events.length : 0;

    trends.push({
      date: day,
      averageRiskScore: avgRisk,
      eventCount: events.length,
    });
  });

  return trends;
}

async function getTopRiskFactors(database: any) {
  const eventsContainer = database.container("security_events");

  const { resources: highRiskEvents } = await eventsContainer.items
    .query("SELECT * FROM c WHERE c.riskScore > 0.5")
    .fetchAll();

  const riskFactors = new Map();

  highRiskEvents.forEach((event: any) => {
    const factor = `${event.type}_${event.severity}`;
    if (!riskFactors.has(factor)) {
      riskFactors.set(factor, { count: 0, totalRisk: 0 });
    }

    const current = riskFactors.get(factor);
    current.count++;
    current.totalRisk += event.riskScore;
  });

  return Array.from(riskFactors.entries())
    .map(([factor, data]: [string, any]) => ({
      factor,
      count: data.count,
      averageRiskScore: data.totalRisk / data.count,
      impact: data.count * (data.totalRisk / data.count),
    }))
    .sort((a, b) => b.impact - a.impact)
    .slice(0, 10);
}

function generateSecurityRecommendations(events: any[], users: any[]) {
  const recommendations = [];

  // Check for users with multiple failed logins
  const usersWithFailures = users.filter(
    (user) => user.failedLoginAttempts > 3
  );
  if (usersWithFailures.length > 0) {
    recommendations.push({
      type: "user_security",
      priority: "high",
      title: "Users with Multiple Failed Login Attempts",
      description: `${usersWithFailures.length} users have multiple failed login attempts. Consider enforcing password resets or account reviews.`,
      affectedUsers: usersWithFailures.length,
    });
  }

  // Check for high-risk events
  const criticalEvents = events.filter(
    (event) => event.severity === "critical"
  );
  if (criticalEvents.length > 0) {
    recommendations.push({
      type: "incident_response",
      priority: "critical",
      title: "Critical Security Events Detected",
      description: `${criticalEvents.length} critical security events require immediate attention.`,
      affectedEvents: criticalEvents.length,
    });
  }

  // Check MFA adoption
  const mfaEnabled = users.filter((user) => user.mfaEnabled);
  const mfaRate = users.length > 0 ? mfaEnabled.length / users.length : 1;
  if (mfaRate < 0.8) {
    recommendations.push({
      type: "mfa_adoption",
      priority: "medium",
      title: "Low MFA Adoption Rate",
      description: `Only ${Math.round(mfaRate * 100)}% of users have MFA enabled. Consider enforcing MFA for all users.`,
      currentRate: Math.round(mfaRate * 100),
    });
  }

  return recommendations;
}

function calculateEventRiskScore(
  type: string,
  severity: string,
  details: any
): number {
  let riskScore = 0;

  // Base risk by severity
  const severityRisk = {
    low: 0.1,
    medium: 0.3,
    high: 0.6,
    critical: 0.9,
  };

  riskScore += severityRisk[severity as keyof typeof severityRisk] || 0.1;

  // Risk by event type
  const typeRisk = {
    login: 0.1,
    logout: 0.0,
    access_denied: 0.4,
    policy_violation: 0.5,
    suspicious_activity: 0.7,
    mfa_challenge: 0.2,
  };

  riskScore += typeRisk[type as keyof typeof typeRisk] || 0.3;

  // Additional risk factors from details
  if (details?.multipleFailedAttempts) {
    riskScore += 0.2;
  }

  if (details?.unusualLocation) {
    riskScore += 0.3;
  }

  if (details?.newDevice) {
    riskScore += 0.2;
  }

  return Math.min(riskScore, 1.0);
}

export default router;
