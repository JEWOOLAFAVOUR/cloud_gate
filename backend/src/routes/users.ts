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

// Get all users (admin only)
router.get(
  "/",
  authenticateToken,
  requirePermission("read:all"),
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("users");

    const { resources: users } = await container.items
      .query(
        `
        SELECT c.id, c.email, c.role, c.mfaEnabled, c.isActive, 
               c.createdAt, c.lastLogin, c.failedLoginAttempts 
        FROM c 
        ORDER BY c.createdAt DESC
      `
      )
      .fetchAll();

    res.json({
      success: true,
      data: users,
    });
  })
);

// Get user by ID
router.get(
  "/:id",
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: any) => {
    const { id } = req.params;
    const user = req.user!;

    // Users can only view their own profile unless they're admin
    if (user.id !== id && user.role !== "admin") {
      throw new AppError("Access denied", 403);
    }

    const cosmosClient = getCosmosClient();
    const database = cosmosClient.database("cloudguard");
    const container = database.container("users");

    const userDoc = await container.item(id).read();

    if (!userDoc.resource) {
      throw new AppError("User not found", 404);
    }

    const userData = userDoc.resource;

    // Remove sensitive data
    delete userData.password;
    delete userData.mfaSecret;

    res.json({
      success: true,
      data: userData,
    });
  })
);

export default router;
