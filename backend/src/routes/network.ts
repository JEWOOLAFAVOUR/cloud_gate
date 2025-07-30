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

// Network interfaces
interface NetworkSegment {
  id: string;
  name: string;
  subnet: string;
  vlan?: number;
  securityLevel: "public" | "internal" | "restricted" | "confidential";
  allowedServices: string[];
  blockedServices: string[];
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

interface TrafficRule {
  id: string;
  name: string;
  sourceSegment: string;
  targetSegment: string;
  protocol: "tcp" | "udp" | "icmp" | "any";
  ports: number[] | string;
  action: "allow" | "deny";
  priority: number;
  isActive: boolean;
  createdAt: Date;
}

// Get network segments
router.get(
  "/segments",
  authenticateToken,
  requirePermission("read:network"),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");

    await database.containers.createIfNotExists({
      id: "network_segments",
      partitionKey: { paths: ["/securityLevel"] },
    });

    const container = database.container("network_segments");

    const { resources: segments } = await container.items
      .query("SELECT * FROM c ORDER BY c.securityLevel, c.name")
      .fetchAll();

    res.json({
      success: true,
      data: segments,
    });
  })
);

// Get traffic rules
router.get(
  "/rules",
  authenticateToken,
  requirePermission("read:network"),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");

    await database.containers.createIfNotExists({
      id: "traffic_rules",
      partitionKey: { paths: ["/action"] },
    });

    const container = database.container("traffic_rules");

    const { resources: rules } = await container.items
      .query("SELECT * FROM c ORDER BY c.priority DESC, c.createdAt")
      .fetchAll();

    res.json({
      success: true,
      data: rules,
    });
  })
);

// Analyze network traffic
router.post(
  "/analyze",
  authenticateToken,
  requirePermission("read:network"),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const { sourceIP, targetIP, port, protocol } = req.body;

    if (!sourceIP || !targetIP || !port || !protocol) {
      throw new AppError(
        "Missing required parameters for traffic analysis",
        400
      );
    }

    // Determine source and target segments
    const sourceSegment = await findSegmentByIP(sourceIP);
    const targetSegment = await findSegmentByIP(targetIP);

    // Check applicable rules
    const rules = await getApplicableRules(
      sourceSegment,
      targetSegment,
      port,
      protocol
    );

    // Determine action (deny takes precedence)
    const denyRule = rules.find((rule) => rule.action === "deny");
    const allowRule = rules.find((rule) => rule.action === "allow");

    const analysis = {
      sourceIP,
      targetIP,
      port,
      protocol,
      sourceSegment,
      targetSegment,
      action: denyRule ? "deny" : allowRule ? "allow" : "default_deny",
      matchedRules: rules,
      riskScore: calculateTrafficRiskScore(
        sourceSegment,
        targetSegment,
        port,
        protocol
      ),
      timestamp: new Date(),
    };

    logger.info(
      `Traffic analysis: ${sourceIP}:${port} -> ${targetIP}:${port} (${protocol}) = ${analysis.action}`
    );

    res.json({
      success: true,
      data: analysis,
    });
  })
);

// Helper functions
async function findSegmentByIP(ip: string): Promise<NetworkSegment | null> {
  const cosmosClient = getCosmosClient();
  const database = cosmosClient.database("cloudguard");
  const container = database.container("network_segments");

  const { resources: segments } = await container.items
    .query("SELECT * FROM c WHERE c.isActive = true")
    .fetchAll();

  for (const segment of segments) {
    if (isIPInSubnet(ip, segment.subnet)) {
      return segment;
    }
  }

  return null;
}

async function getApplicableRules(
  sourceSegment: NetworkSegment | null,
  targetSegment: NetworkSegment | null,
  port: number,
  protocol: string
): Promise<TrafficRule[]> {
  if (!sourceSegment || !targetSegment) {
    return [];
  }

  const cosmosClient = getCosmosClient();
  const database = cosmosClient.database("cloudguard");
  const container = database.container("traffic_rules");

  const { resources: allRules } = await container.items
    .query("SELECT * FROM c WHERE c.isActive = true ORDER BY c.priority DESC")
    .fetchAll();

  return allRules.filter(
    (rule) =>
      (rule.sourceSegment === sourceSegment.id || rule.sourceSegment === "*") &&
      (rule.targetSegment === targetSegment.id || rule.targetSegment === "*") &&
      (rule.protocol === protocol || rule.protocol === "any") &&
      isPortInRange(port, rule.ports)
  );
}

function isIPInSubnet(ip: string, subnet: string): boolean {
  const [subnetIP, prefix] = subnet.split("/");
  const prefixLength = parseInt(prefix);

  const ipInt = ipToInt(ip);
  const subnetInt = ipToInt(subnetIP);
  const mask = (0xffffffff << (32 - prefixLength)) >>> 0;

  return (ipInt & mask) === (subnetInt & mask);
}

function ipToInt(ip: string): number {
  return (
    ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0
  );
}

function isPortInRange(port: number, portRange: number[] | string): boolean {
  if (typeof portRange === "string") {
    if (portRange === "any" || portRange === "*") return true;

    if (portRange.includes("-")) {
      const [start, end] = portRange.split("-").map((p) => parseInt(p));
      return port >= start && port <= end;
    }

    return port === parseInt(portRange);
  }

  if (Array.isArray(portRange)) {
    return portRange.includes(port);
  }

  return false;
}

function calculateTrafficRiskScore(
  sourceSegment: NetworkSegment | null,
  targetSegment: NetworkSegment | null,
  port: number,
  protocol: string
): number {
  let riskScore = 0;

  // Security level crossing risk
  const securityLevels = {
    public: 1,
    internal: 2,
    restricted: 3,
    confidential: 4,
  };

  if (sourceSegment && targetSegment) {
    const sourceLevel = securityLevels[sourceSegment.securityLevel];
    const targetLevel = securityLevels[targetSegment.securityLevel];

    if (sourceLevel < targetLevel) {
      riskScore += 0.3; // Lower security level accessing higher
    }
  }

  // High-risk ports
  const highRiskPorts = [22, 23, 135, 139, 445, 1433, 1521, 3389, 5432];
  if (highRiskPorts.includes(port)) {
    riskScore += 0.2;
  }

  // Protocol risk
  if (protocol === "tcp" && [21, 23, 80, 513, 514, 515].includes(port)) {
    riskScore += 0.1; // Unencrypted protocols
  }

  return Math.min(riskScore, 1.0);
}

export default router;
