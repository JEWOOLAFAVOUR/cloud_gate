import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import { AppError } from "./errorHandler";
import { getSession } from "../utils/redis";
import { logger } from "../utils/logger";

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
    permissions: string[];
    deviceId?: string;
    sessionId: string;
    lastActivity: Date;
    riskScore: number;
  };
}

export interface JWTPayload {
  userId: string;
  email: string;
  role: string;
  permissions: string[];
  sessionId: string;
  deviceId?: string;
  iat: number;
  exp: number;
}

export const generateTokens = (payload: Omit<JWTPayload, "iat" | "exp">) => {
  const jwtSecret =
    process.env.JWT_SECRET || "default-secret-key-for-development";
  const jwtRefreshSecret =
    process.env.JWT_REFRESH_SECRET || "default-refresh-secret-for-development";

  const accessToken = jwt.sign(payload, jwtSecret, { expiresIn: "15m" });

  const refreshToken = jwt.sign(
    { userId: payload.userId, sessionId: payload.sessionId },
    jwtRefreshSecret,
    { expiresIn: "7d" }
  );

  return { accessToken, refreshToken };
};

export const verifyToken = (token: string): JWTPayload => {
  const jwtSecret =
    process.env.JWT_SECRET || "default-secret-key-for-development";

  try {
    return jwt.verify(token, jwtSecret) as JWTPayload;
  } catch (error) {
    throw new AppError("Invalid or expired token", 401);
  }
};

export const verifyRefreshToken = (token: string) => {
  const jwtRefreshSecret =
    process.env.JWT_REFRESH_SECRET || "default-refresh-secret-for-development";

  try {
    return jwt.verify(token, jwtRefreshSecret) as {
      userId: string;
      sessionId: string;
      iat: number;
      exp: number;
    };
  } catch (error) {
    throw new AppError("Invalid or expired refresh token", 401);
  }
};

export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.substring(7)
      : null;

    if (!token) {
      throw new AppError("Access token required", 401);
    }

    // Verify JWT token
    const decoded = verifyToken(token);

    // Check session validity
    const session = await getSession(decoded.sessionId);
    if (!session) {
      throw new AppError("Session expired or invalid", 401);
    }

    // Check device binding (if enabled)
    const deviceId = req.headers["x-device-id"] as string;
    if (decoded.deviceId && decoded.deviceId !== deviceId) {
      logger.warn(
        `Device mismatch for user ${decoded.userId}. Expected: ${decoded.deviceId}, Got: ${deviceId}`
      );
      throw new AppError("Device verification failed", 401);
    }

    // Calculate risk score based on various factors
    const riskScore = calculateRiskScore(req, session);

    // If risk score is too high, require re-authentication
    if (riskScore > 0.8) {
      throw new AppError("High risk detected, re-authentication required", 401);
    }

    // Update user context
    req.user = {
      id: decoded.userId,
      email: decoded.email,
      role: decoded.role,
      permissions: decoded.permissions,
      deviceId: decoded.deviceId,
      sessionId: decoded.sessionId,
      lastActivity: new Date(),
      riskScore,
    };

    // Update session last activity
    session.lastActivity = new Date();
    await require("../utils/redis").setSession(decoded.sessionId, session, 900);

    next();
  } catch (error) {
    next(error);
  }
};

export const requirePermission = (permission: string) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    if (
      !req.user.permissions.includes(permission) &&
      req.user.role !== "admin"
    ) {
      return next(new AppError("Insufficient permissions", 403));
    }

    next();
  };
};

export const requireRole = (role: string) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    if (req.user.role !== role && req.user.role !== "admin") {
      return next(new AppError("Insufficient role privileges", 403));
    }

    next();
  };
};

// Risk scoring algorithm
const calculateRiskScore = (req: Request, session: any): number => {
  let riskScore = 0;

  // Check for unusual IP address
  const currentIP = req.ip;
  if (session.knownIPs && !session.knownIPs.includes(currentIP)) {
    riskScore += 0.3;
  }

  // Check for unusual user agent
  const currentUserAgent = req.get("User-Agent");
  if (
    session.knownUserAgents &&
    !session.knownUserAgents.includes(currentUserAgent)
  ) {
    riskScore += 0.2;
  }

  // Check time since last activity
  const lastActivity = new Date(session.lastActivity);
  const timeDiff = Date.now() - lastActivity.getTime();
  const hoursSinceLastActivity = timeDiff / (1000 * 60 * 60);

  if (hoursSinceLastActivity > 24) {
    riskScore += 0.3;
  } else if (hoursSinceLastActivity > 8) {
    riskScore += 0.1;
  }

  // Check for rapid successive requests (potential automation)
  const now = Date.now();
  if (!session.requestTimestamps) {
    session.requestTimestamps = [];
  }

  session.requestTimestamps.push(now);
  session.requestTimestamps = session.requestTimestamps.filter(
    (timestamp: number) => now - timestamp < 60000 // Keep only last minute
  );

  if (session.requestTimestamps.length > 50) {
    riskScore += 0.4;
  }

  return Math.min(riskScore, 1.0); // Cap at 1.0
};
