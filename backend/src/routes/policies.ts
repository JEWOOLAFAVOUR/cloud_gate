import express from "express";
import { body, param, validationResult } from "express-validator";
import { v4 as uuidv4 } from "uuid";
import { AppError, asyncHandler } from "../middleware/errorHandler";
import {
  authenticateToken,
  requirePermission,
  AuthenticatedRequest,
} from "../middleware/auth";
import { getCosmosClient } from "../utils/azure";
import { logger } from "../utils/logger";

const router = express.Router();

// Policy interfaces
interface SecurityPolicy {
  id: string;
  name: string;
  description: string;
  type: "access" | "network" | "authentication" | "data";
  rules: PolicyRule[];
  conditions: PolicyCondition[];
  actions: PolicyAction[];
  priority: number;
  isActive: boolean;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
  version: number;
}

interface PolicyRule {
  id: string;
  type: string;
  field: string;
  operator:
    | "equals"
    | "not_equals"
    | "contains"
    | "not_contains"
    | "greater_than"
    | "less_than"
    | "in"
    | "not_in";
  value: any;
  logicalOperator?: "AND" | "OR";
}

interface PolicyCondition {
  id: string;
  type: "time" | "location" | "device" | "user" | "network" | "risk_score";
  parameters: Record<string, any>;
}

interface PolicyAction {
  id: string;
  type: "allow" | "deny" | "challenge" | "log" | "alert" | "quarantine";
  parameters: Record<string, any>;
}

// Validation middleware
const validatePolicy = [
  body("name").notEmpty().trim(),
  body("description").notEmpty().trim(),
  body("type").isIn(["access", "network", "authentication", "data"]),
  body("rules").isArray(),
  body("priority").isInt({ min: 1, max: 100 }),
];

// Get all policies
router.get(
  "/",
  authenticateToken,
  requirePermission("read:policies"),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");

    await database.containers.createIfNotExists({
      id: "policies",
      partitionKey: { paths: ["/type"] },
    });

    const container = database.container("policies");

    const { resources: policies } = await container.items
      .query("SELECT * FROM c ORDER BY c.priority DESC, c.createdAt DESC")
      .fetchAll();

    res.json({
      success: true,
      data: policies,
    });
  })
);

// Get policy by ID
router.get(
  "/:id",
  authenticateToken,
  requirePermission("read:policies"),
  param("id").isUUID(),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new AppError("Invalid policy ID", 400);
    }

    const { id } = req.params;
    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("policies");

    const querySpec = {
      query: "SELECT * FROM c WHERE c.id = @id",
      parameters: [{ name: "@id", value: id }],
    };

    const { resources: policies } = await container.items
      .query(querySpec)
      .fetchAll();

    if (policies.length === 0) {
      throw new AppError("Policy not found", 404);
    }

    res.json({
      success: true,
      data: policies[0],
    });
  })
);

// Create new policy
router.post(
  "/",
  authenticateToken,
  requirePermission("create:policies"),
  validatePolicy,
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new AppError("Validation failed", 400);
    }

    const { name, description, type, rules, conditions, actions, priority } =
      req.body;
    const user = req.user!;

    const policy: SecurityPolicy = {
      id: uuidv4(),
      name,
      description,
      type,
      rules: rules.map((rule: any) => ({ ...rule, id: uuidv4() })),
      conditions:
        conditions?.map((condition: any) => ({ ...condition, id: uuidv4() })) ||
        [],
      actions:
        actions?.map((action: any) => ({ ...action, id: uuidv4() })) || [],
      priority,
      isActive: true,
      createdBy: user.id,
      createdAt: new Date(),
      updatedAt: new Date(),
      version: 1,
    };

    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("policies");

    await container.items.create(policy);

    logger.info(`New policy created: ${name} by ${user.email}`);

    res.status(201).json({
      success: true,
      message: "Policy created successfully",
      data: policy,
    });
  })
);

// Update policy
router.put(
  "/:id",
  authenticateToken,
  requirePermission("update:policies"),
  param("id").isUUID(),
  validatePolicy,
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new AppError("Validation failed", 400);
    }

    const { id } = req.params;
    const { name, description, type, rules, conditions, actions, priority } =
      req.body;
    const user = req.user!;

    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("policies");

    const querySpec = {
      query: "SELECT * FROM c WHERE c.id = @id",
      parameters: [{ name: "@id", value: id }],
    };

    const { resources: policies } = await container.items
      .query(querySpec)
      .fetchAll();

    if (policies.length === 0) {
      throw new AppError("Policy not found", 404);
    }

    const existingPolicy = policies[0];

    const updatedPolicy: SecurityPolicy = {
      ...existingPolicy,
      name,
      description,
      type,
      rules: rules.map((rule: any) => ({ ...rule, id: rule.id || uuidv4() })),
      conditions:
        conditions?.map((condition: any) => ({
          ...condition,
          id: condition.id || uuidv4(),
        })) || [],
      actions:
        actions?.map((action: any) => ({
          ...action,
          id: action.id || uuidv4(),
        })) || [],
      priority,
      updatedAt: new Date(),
      version: existingPolicy.version + 1,
    };

    await container.item(id, type).replace(updatedPolicy);

    logger.info(`Policy updated: ${name} by ${user.email}`);

    res.json({
      success: true,
      message: "Policy updated successfully",
      data: updatedPolicy,
    });
  })
);

// Toggle policy status
router.patch(
  "/:id/toggle",
  authenticateToken,
  requirePermission("update:policies"),
  param("id").isUUID(),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new AppError("Invalid policy ID", 400);
    }

    const { id } = req.params;
    const user = req.user!;

    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("policies");

    const policyDoc = await container.item(id).read();

    if (!policyDoc.resource) {
      throw new AppError("Policy not found", 404);
    }

    const policy = policyDoc.resource;
    policy.isActive = !policy.isActive;
    policy.updatedAt = new Date();
    policy.version += 1;

    await container.item(id, policy.type).replace(policy);

    logger.info(
      `Policy ${policy.isActive ? "activated" : "deactivated"}: ${policy.name} by ${user.email}`
    );

    res.json({
      success: true,
      message: `Policy ${policy.isActive ? "activated" : "deactivated"} successfully`,
      data: { id, isActive: policy.isActive },
    });
  })
);

// Delete policy
router.delete(
  "/:id",
  authenticateToken,
  requirePermission("delete:policies"),
  param("id").isUUID(),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new AppError("Invalid policy ID", 400);
    }

    const { id } = req.params;
    const user = req.user!;

    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("policies");

    const policyDoc = await container.item(id).read();

    if (!policyDoc.resource) {
      throw new AppError("Policy not found", 404);
    }

    await container.item(id, policyDoc.resource.type).delete();

    logger.info(`Policy deleted: ${policyDoc.resource.name} by ${user.email}`);

    res.json({
      success: true,
      message: "Policy deleted successfully",
    });
  })
);

// Evaluate policies for a given context
router.post(
  "/evaluate",
  authenticateToken,
  requirePermission("read:policies"),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const { context } = req.body;

    if (!context) {
      throw new AppError("Context is required for policy evaluation", 400);
    }

    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("policies");

    // Get active policies sorted by priority
    const { resources: policies } = await container.items
      .query("SELECT * FROM c WHERE c.isActive = true ORDER BY c.priority DESC")
      .fetchAll();

    const evaluationResults = [];

    for (const policy of policies) {
      const result = await evaluatePolicy(policy, context);
      evaluationResults.push({
        policyId: policy.id,
        policyName: policy.name,
        result: result.decision,
        actions: result.actions,
        matchedRules: result.matchedRules,
      });

      // If policy denies access, stop evaluation (fail-closed)
      if (result.decision === "deny") {
        break;
      }
    }

    const finalDecision = evaluationResults.some((r) => r.result === "deny")
      ? "deny"
      : "allow";

    res.json({
      success: true,
      data: {
        decision: finalDecision,
        evaluationResults,
        context,
        timestamp: new Date(),
      },
    });
  })
);

// Policy evaluation engine
async function evaluatePolicy(policy: SecurityPolicy, context: any) {
  const matchedRules = [];
  let ruleMatches = 0;

  // Evaluate rules
  for (const rule of policy.rules) {
    const isMatch = evaluateRule(rule, context);
    if (isMatch) {
      matchedRules.push(rule);
      ruleMatches++;
    }
  }

  // Evaluate conditions
  const conditionResults = [];
  for (const condition of policy.conditions) {
    const result = await evaluateCondition(condition, context);
    conditionResults.push(result);
  }

  // Determine if policy applies
  const allRulesMatch = ruleMatches === policy.rules.length;
  const allConditionsMatch = conditionResults.every((r) => r === true);

  let decision = "allow";
  let triggeredActions = [];

  if (allRulesMatch && allConditionsMatch) {
    // Policy applies, execute actions
    for (const action of policy.actions) {
      if (action.type === "deny") {
        decision = "deny";
      }
      triggeredActions.push(action);
    }
  }

  return {
    decision,
    actions: triggeredActions,
    matchedRules,
    conditionResults,
  };
}

function evaluateRule(rule: PolicyRule, context: any): boolean {
  const contextValue = getNestedValue(context, rule.field);

  switch (rule.operator) {
    case "equals":
      return contextValue === rule.value;
    case "not_equals":
      return contextValue !== rule.value;
    case "contains":
      return String(contextValue).includes(rule.value);
    case "not_contains":
      return !String(contextValue).includes(rule.value);
    case "greater_than":
      return Number(contextValue) > Number(rule.value);
    case "less_than":
      return Number(contextValue) < Number(rule.value);
    case "in":
      return Array.isArray(rule.value) && rule.value.includes(contextValue);
    case "not_in":
      return Array.isArray(rule.value) && !rule.value.includes(contextValue);
    default:
      return false;
  }
}

async function evaluateCondition(
  condition: PolicyCondition,
  context: any
): Promise<boolean> {
  switch (condition.type) {
    case "time":
      return evaluateTimeCondition(condition.parameters, context);
    case "location":
      return evaluateLocationCondition(condition.parameters, context);
    case "device":
      return evaluateDeviceCondition(condition.parameters, context);
    case "user":
      return evaluateUserCondition(condition.parameters, context);
    case "network":
      return evaluateNetworkCondition(condition.parameters, context);
    case "risk_score":
      return evaluateRiskScoreCondition(condition.parameters, context);
    default:
      return true;
  }
}

function evaluateTimeCondition(params: any, context: any): boolean {
  const now = new Date();
  const currentHour = now.getHours();
  const currentDay = now.getDay(); // 0 = Sunday

  if (params.allowedHours) {
    const [startHour, endHour] = params.allowedHours;
    if (currentHour < startHour || currentHour > endHour) {
      return false;
    }
  }

  if (params.allowedDays) {
    if (!params.allowedDays.includes(currentDay)) {
      return false;
    }
  }

  return true;
}

function evaluateLocationCondition(params: any, context: any): boolean {
  // Implement geolocation-based access control
  const userLocation = context.location;
  if (!userLocation) return true;

  if (params.allowedCountries) {
    return params.allowedCountries.includes(userLocation.country);
  }

  if (params.blockedCountries) {
    return !params.blockedCountries.includes(userLocation.country);
  }

  return true;
}

function evaluateDeviceCondition(params: any, context: any): boolean {
  const device = context.device;
  if (!device) return true;

  if (params.trustedDevicesOnly && !device.isTrusted) {
    return false;
  }

  if (params.maxRiskScore && device.riskScore > params.maxRiskScore) {
    return false;
  }

  return true;
}

function evaluateUserCondition(params: any, context: any): boolean {
  const user = context.user;
  if (!user) return false;

  if (params.requiredRoles) {
    return params.requiredRoles.includes(user.role);
  }

  if (params.requiredPermissions) {
    return params.requiredPermissions.every((perm: string) =>
      user.permissions.includes(perm)
    );
  }

  return true;
}

function evaluateNetworkCondition(params: any, context: any): boolean {
  const network = context.network;
  if (!network) return true;

  if (params.allowedNetworks) {
    return params.allowedNetworks.some((subnet: string) =>
      isIPInSubnet(network.ip, subnet)
    );
  }

  if (params.blockedNetworks) {
    return !params.blockedNetworks.some((subnet: string) =>
      isIPInSubnet(network.ip, subnet)
    );
  }

  return true;
}

function evaluateRiskScoreCondition(params: any, context: any): boolean {
  const riskScore = context.riskScore || 0;

  if (params.maxRiskScore) {
    return riskScore <= params.maxRiskScore;
  }

  return true;
}

function getNestedValue(obj: any, path: string): any {
  return path.split(".").reduce((current, key) => current?.[key], obj);
}

function isIPInSubnet(ip: string, subnet: string): boolean {
  // Simplified IP subnet check - in production, use a proper library
  const [subnetIP, prefix] = subnet.split("/");
  const prefixLength = parseInt(prefix);

  // Convert IPs to integers for comparison
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

export default router;
