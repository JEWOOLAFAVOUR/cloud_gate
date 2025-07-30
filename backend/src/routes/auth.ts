import express from "express";
// Remove bcrypt import
// import bcrypt from "bcryptjs";
import crypto from "crypto";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import { v4 as uuidv4 } from "uuid";
import { body, validationResult } from "express-validator";
import { AppError, asyncHandler } from "../middleware/errorHandler";
import {
  generateTokens,
  verifyRefreshToken,
  AuthenticatedRequest,
  authenticateToken,
} from "../middleware/auth";
import { setSession, getSession, deleteSession } from "../utils/redis";
import { getCosmosClient } from "../utils/azure";
import { logger } from "../utils/logger";

const router = express.Router();

// Simple crypto-based password hashing
function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .pbkdf2Sync(password, salt, 1000, 64, "sha512")
    .toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password: string, hashedPassword: string): boolean {
  const [salt, hash] = hashedPassword.split(":");
  const verifyHash = crypto
    .pbkdf2Sync(password, salt, 1000, 64, "sha512")
    .toString("hex");
  return hash === verifyHash;
}

// User model interfaces
interface User {
  id: string;
  email: string;
  password: string;
  role: string;
  permissions: string[];
  mfaSecret?: string;
  mfaEnabled: boolean;
  isActive: boolean;
  createdAt: Date;
  lastLogin?: Date;
  failedLoginAttempts: number;
  lockoutUntil?: Date;
  knownDevices: string[];
}

interface Device {
  id: string;
  userId: string;
  fingerprint: string;
  userAgent: string;
  lastSeen: Date;
  isActive: boolean;
  riskScore: number;
}

// Validation middleware
const validateRegistration = [
  body("email").isEmail().normalizeEmail(),
  body("password")
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/),
  body("role").isIn(["user", "admin", "security_analyst"]),
];

const validateLogin = [
  body("email").isEmail().normalizeEmail(),
  body("password").notEmpty(),
];

// Register new user
router.post(
  "/register",
  validateRegistration,
  asyncHandler(async (req: any, res: any) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new AppError("Validation failed", 400);
    }

    const { email, password, role = "user" } = req.body;

    // Check if user already exists
    const cosmosClient = getCosmosClient();
    const { database } = await cosmosClient.databases.createIfNotExists({
      id: "cloudguard",
    });
    const { container } = await database.containers.createIfNotExists({
      id: "users",
      partitionKey: { paths: ["/email"] },
    });

    const querySpec = {
      query: "SELECT * FROM c WHERE c.email = @email",
      parameters: [{ name: "@email", value: email }],
    };

    const { resources: existingUsers } = await container.items
      .query(querySpec)
      .fetchAll();

    if (existingUsers.length > 0) {
      throw new AppError("User already exists", 409);
    }

    // Hash password using crypto
    const hashedPassword = hashPassword(password);

    // Create user
    const userId = uuidv4();
    const user: User = {
      id: userId,
      email,
      password: hashedPassword,
      role,
      permissions: getDefaultPermissions(role),
      mfaEnabled: false,
      isActive: true,
      createdAt: new Date(),
      failedLoginAttempts: 0,
      knownDevices: [],
    };

    await container.items.create(user);

    logger.info(`New user registered: ${email}`);

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      data: {
        id: user.id,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled,
      },
    });
  })
);

// Login user
router.post(
  "/login",
  validateLogin,
  asyncHandler(async (req: any, res: any) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new AppError("Validation failed", 400);
    }

    const { email, password, mfaToken, deviceFingerprint } = req.body;

    // MVP Mode - Use mock authentication
    if (
      process.env.MVP_MODE === "true" ||
      process.env.NODE_ENV === "development"
    ) {
      // Mock user for demo - using plain text password for simplicity
      const mockUser = {
        id: "admin-123",
        email: "admin@cloudguard.com",
        password: "password123", // Plain text for MVP
        role: "admin",
        permissions: ["read", "write", "admin"],
        isActive: true,
        lastLogin: new Date(),
        mfaEnabled: false,
      };

      // Check credentials
      if (email !== mockUser.email) {
        throw new AppError("Invalid credentials", 401);
      }

      // Simple password comparison for MVP
      if (password !== mockUser.password) {
        throw new AppError("Invalid credentials", 401);
      }

      // Generate session ID and tokens
      const sessionId = crypto.randomUUID();
      const tokenPayload = {
        userId: mockUser.id,
        email: mockUser.email,
        role: mockUser.role,
        permissions: mockUser.permissions,
        sessionId,
        deviceId: deviceFingerprint,
      };

      const { accessToken, refreshToken } = generateTokens(tokenPayload);

      logger.info(`Successful login for user ${mockUser.email}`);

      res.json({
        success: true,
        data: {
          user: {
            id: mockUser.id,
            email: mockUser.email,
            role: mockUser.role,
            permissions: mockUser.permissions,
          },
          accessToken,
          refreshToken,
          expiresIn: process.env.JWT_EXPIRES_IN || "15m",
        },
      });
      return;
    }

    // Production mode - Use Cosmos DB with crypto hashing
    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("users");

    const querySpec = {
      query: "SELECT * FROM c WHERE c.email = @email",
      parameters: [{ name: "@email", value: email }],
    };

    const { resources: users } = await container.items
      .query(querySpec)
      .fetchAll();

    if (users.length === 0) {
      throw new AppError("Invalid credentials", 401);
    }

    const user = users[0] as User;

    // Check if account is locked
    if (user.lockoutUntil && user.lockoutUntil > new Date()) {
      throw new AppError("Account temporarily locked", 423);
    }

    // Verify password using crypto
    const isPasswordValid = verifyPassword(password, user.password);

    if (!isPasswordValid) {
      // Increment failed login attempts
      user.failedLoginAttempts += 1;

      if (user.failedLoginAttempts >= 5) {
        user.lockoutUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      }

      await container.item(user.id, user.email).replace(user);
      throw new AppError("Invalid credentials", 401);
    }

    // Check MFA if enabled
    if (user.mfaEnabled) {
      if (!mfaToken) {
        throw new AppError("MFA token required", 401);
      }

      const verified = speakeasy.totp.verify({
        secret: user.mfaSecret!,
        encoding: "base32",
        token: mfaToken,
        window: parseInt(process.env.MFA_WINDOW || "2"),
      });

      if (!verified) {
        throw new AppError("Invalid MFA token", 401);
      }
    }

    // Device verification
    const deviceId = await verifyOrRegisterDevice(
      user.id,
      deviceFingerprint,
      req
    );

    // Reset failed login attempts
    user.failedLoginAttempts = 0;
    user.lockoutUntil = undefined;
    user.lastLogin = new Date();
    await container.item(user.id, user.email).replace(user);

    // Create session
    const sessionId = uuidv4();
    const sessionData = {
      userId: user.id,
      email: user.email,
      role: user.role,
      deviceId,
      createdAt: new Date(),
      lastActivity: new Date(),
      knownIPs: [req.ip],
      knownUserAgents: [req.get("User-Agent")],
      requestTimestamps: [],
    };

    await setSession(sessionId, sessionData, 900); // 15 minutes

    // Generate tokens
    const tokens = generateTokens({
      userId: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      sessionId,
      deviceId,
    });

    logger.info(`User logged in: ${email}`);

    res.json({
      success: true,
      message: "Login successful",
      data: {
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          permissions: user.permissions,
          mfaEnabled: user.mfaEnabled,
        },
        tokens,
        sessionId,
      },
    });
  })
);

// Setup MFA
router.post(
  "/setup-mfa",
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const user = req.user!;

    // Generate MFA secret
    const secret = speakeasy.generateSecret({
      issuer: process.env.MFA_ISSUER || "CloudGuard",
      name: user.email,
      length: 32,
    });

    // Generate QR code
    const qrCodeDataURL = await QRCode.toDataURL(secret.otpauth_url!);

    // Store secret temporarily (not saved to user until verified)
    await setSession(`mfa-setup-${user.id}`, { secret: secret.base32 }, 300); // 5 minutes

    res.json({
      success: true,
      data: {
        secret: secret.base32,
        qrCode: qrCodeDataURL,
        backupCodes: generateBackupCodes(),
      },
    });
  })
);

// Verify and enable MFA
router.post(
  "/verify-mfa",
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const { token } = req.body;
    const user = req.user!;

    // Get temporary secret
    const setupData = await getSession(`mfa-setup-${user.id}`);
    if (!setupData) {
      throw new AppError("MFA setup session expired", 400);
    }

    // Verify token
    const verified = speakeasy.totp.verify({
      secret: setupData.secret,
      encoding: "base32",
      token,
      window: parseInt(process.env.MFA_WINDOW || "2"),
    });

    if (!verified) {
      throw new AppError("Invalid MFA token", 400);
    }

    // Enable MFA for user
    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("users");

    const userDoc = await container.item(user.id, user.email).read();
    const userData = userDoc.resource;

    userData.mfaSecret = setupData.secret;
    userData.mfaEnabled = true;

    await container.item(user.id, user.email).replace(userData);

    // Clean up setup session
    await deleteSession(`mfa-setup-${user.id}`);

    logger.info(`MFA enabled for user: ${user.email}`);

    res.json({
      success: true,
      message: "MFA enabled successfully",
    });
  })
);

// Refresh token
router.post(
  "/refresh",
  asyncHandler(async (req: any, res: any) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      throw new AppError("Refresh token required", 401);
    }

    // Verify refresh token
    const decoded = verifyRefreshToken(refreshToken);

    // Check session
    const session = await getSession(decoded.sessionId);
    if (!session) {
      throw new AppError("Session expired", 401);
    }

    // Get user data
    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("users");

    const userDoc = await container.item(decoded.userId, session.email).read();
    const user = userDoc.resource;

    // Generate new tokens
    const tokens = generateTokens({
      userId: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      sessionId: decoded.sessionId,
      deviceId: session.deviceId,
    });

    res.json({
      success: true,
      data: { tokens },
    });
  })
);

// Logout
router.post(
  "/logout",
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const user = req.user!;

    // Delete session
    await deleteSession(user.sessionId);

    logger.info(`User logged out: ${user.email}`);

    res.json({
      success: true,
      message: "Logged out successfully",
    });
  })
);

// Get current user profile
router.get(
  "/profile",
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const user = req.user!;

    res.json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        lastActivity: user.lastActivity,
        riskScore: user.riskScore,
      },
    });
  })
);

// Helper functions
function getDefaultPermissions(role: string): string[] {
  const permissions = {
    user: ["read:own", "update:own"],
    security_analyst: ["read:all", "update:security", "create:policies"],
    admin: ["*"],
  };

  return permissions[role as keyof typeof permissions] || permissions.user;
}

async function verifyOrRegisterDevice(
  userId: string,
  fingerprint: string,
  req: any
): Promise<string> {
  const cosmosClient = getCosmosClient();
  const database = cosmosClient.database("cloudguard");

  // Create devices container if not exists
  await database.containers.createIfNotExists({
    id: "devices",
    partitionKey: { paths: ["/userId"] },
  });

  const container = database.container("devices");

  const querySpec = {
    query:
      "SELECT * FROM c WHERE c.userId = @userId AND c.fingerprint = @fingerprint",
    parameters: [
      { name: "@userId", value: userId },
      { name: "@fingerprint", value: fingerprint },
    ],
  };

  const { resources: devices } = await container.items
    .query(querySpec)
    .fetchAll();

  if (devices.length > 0) {
    // Update existing device
    const device = devices[0];
    device.lastSeen = new Date();
    device.isActive = true;
    await container.item(device.id, device.userId).replace(device);
    return device.id;
  } else {
    // Register new device
    const deviceId = uuidv4();
    const device: Device = {
      id: deviceId,
      userId,
      fingerprint,
      userAgent: req.get("User-Agent") || "",
      lastSeen: new Date(),
      isActive: true,
      riskScore: 0.2, // New devices have moderate risk
    };

    await container.items.create(device);
    return deviceId;
  }
}

function generateBackupCodes(): string[] {
  const codes = [];
  for (let i = 0; i < 10; i++) {
    codes.push(Math.random().toString(36).substring(2, 10).toUpperCase());
  }
  return codes;
}

export default router;
