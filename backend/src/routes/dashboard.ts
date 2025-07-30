import express from "express";
import { authenticateToken, AuthenticatedRequest } from "../middleware/auth";
import { logger } from "../utils/logger";

const router = express.Router();

// Get dashboard metrics
router.get(
  "/metrics",
  authenticateToken,
  async (req: AuthenticatedRequest, res) => {
    try {
      // Mock dashboard metrics for MVP
      const metrics = {
        totalUsers: 1247,
        activeUsers: 89,
        policiesEnforced: 156,
        securityScore: 94,
        threatLevel: "low",
        lastUpdated: new Date().toISOString(),
      };

      logger.info(`Dashboard metrics requested by user ${req.user?.id}`);

      res.json({
        success: true,
        data: metrics,
      });
    } catch (error) {
      logger.error("Dashboard metrics error:", error);
      res.status(500).json({
        success: false,
        error: "Failed to fetch dashboard metrics",
      });
    }
  }
);

// Get dashboard summary
router.get(
  "/summary",
  authenticateToken,
  async (req: AuthenticatedRequest, res) => {
    try {
      const summary = {
        alerts: {
          critical: 2,
          warning: 5,
          info: 12,
        },
        activity: {
          loginAttempts: 234,
          successfulLogins: 198,
          failedLogins: 36,
        },
        compliance: {
          score: 94,
          policies: {
            total: 156,
            enforced: 150,
            violations: 6,
          },
        },
      };

      res.json({
        success: true,
        data: summary,
      });
    } catch (error) {
      logger.error("Dashboard summary error:", error);
      res.status(500).json({
        success: false,
        error: "Failed to fetch dashboard summary",
      });
    }
  }
);

export default router;
