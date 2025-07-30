import { createClient } from "redis";
import { logger } from "./logger";

let redisClient: any;

export const connectRedis = async () => {
  try {
    redisClient = createClient({
      url: process.env.REDIS_URL || "redis://localhost:6379",
    });

    redisClient.on("error", (err: Error) => {
      logger.warn("Redis Client Error (Redis optional for MVP):", err.message);
    });

    redisClient.on("connect", () => {
      logger.info("Connected to Redis");
    });

    await redisClient.connect();
    return redisClient;
  } catch (error) {
    logger.warn(
      "Failed to connect to Redis (continuing without Redis):",
      error
    );
    // Don't throw error - continue without Redis
    return null;
  }
};

export const getRedisClient = () => {
  if (!redisClient) {
    throw new Error("Redis client not initialized");
  }
  return redisClient;
};

// Session management
export const setSession = async (
  sessionId: string,
  data: any,
  ttl: number = 900
) => {
  try {
    await redisClient.setEx(sessionId, ttl, JSON.stringify(data));
  } catch (error) {
    logger.error("Error setting session:", error);
    throw error;
  }
};

export const getSession = async (sessionId: string) => {
  try {
    const data = await redisClient.get(sessionId);
    return data ? JSON.parse(data) : null;
  } catch (error) {
    logger.error("Error getting session:", error);
    throw error;
  }
};

export const deleteSession = async (sessionId: string) => {
  try {
    await redisClient.del(sessionId);
  } catch (error) {
    logger.error("Error deleting session:", error);
    throw error;
  }
};

// Rate limiting
export const incrementRateLimit = async (
  identifier: string,
  window: number = 900
) => {
  try {
    const multi = redisClient.multi();
    multi.incr(identifier);
    multi.expire(identifier, window);
    const results = await multi.exec();
    return results[0] as number;
  } catch (error) {
    logger.error("Error incrementing rate limit:", error);
    throw error;
  }
};

export const getRateLimit = async (identifier: string) => {
  try {
    return await redisClient.get(identifier);
  } catch (error) {
    logger.error("Error getting rate limit:", error);
    throw error;
  }
};
