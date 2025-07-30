import { DefaultAzureCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";
import { BlobServiceClient } from "@azure/storage-blob";
import { CosmosClient } from "@azure/cosmos";
import { logger } from "./logger";

let secretClient: SecretClient;
let blobServiceClient: BlobServiceClient;
let cosmosClient: CosmosClient;

export const initializeAzureServices = async () => {
  try {
    // Initialize Azure credentials
    const credential = new DefaultAzureCredential();

    // Initialize Key Vault client
    if (process.env.AZURE_KEY_VAULT_URL) {
      secretClient = new SecretClient(
        process.env.AZURE_KEY_VAULT_URL,
        credential
      );
      logger.info("Azure Key Vault client initialized");
    }

    // Initialize Blob Storage client
    if (process.env.AZURE_STORAGE_CONNECTION_STRING) {
      blobServiceClient = BlobServiceClient.fromConnectionString(
        process.env.AZURE_STORAGE_CONNECTION_STRING
      );
      logger.info("Azure Blob Storage client initialized");
    }

    // Initialize Cosmos DB client
    if (process.env.DB_CONNECTION_STRING) {
      cosmosClient = new CosmosClient(process.env.DB_CONNECTION_STRING);
      logger.info("Azure Cosmos DB client initialized");
    }

    logger.info("Azure services initialized successfully");
  } catch (error) {
    logger.error("Failed to initialize Azure services:", error);
    throw error;
  }
};

// Key Vault operations
export const getSecret = async (
  secretName: string
): Promise<string | undefined> => {
  try {
    if (!secretClient) {
      throw new Error("Key Vault client not initialized");
    }
    const secret = await secretClient.getSecret(secretName);
    return secret.value;
  } catch (error) {
    logger.error(`Error retrieving secret ${secretName}:`, error);
    throw error;
  }
};

export const setSecret = async (
  secretName: string,
  secretValue: string
): Promise<void> => {
  try {
    if (!secretClient) {
      throw new Error("Key Vault client not initialized");
    }
    await secretClient.setSecret(secretName, secretValue);
    logger.info(`Secret ${secretName} stored successfully`);
  } catch (error) {
    logger.error(`Error storing secret ${secretName}:`, error);
    throw error;
  }
};

// Blob Storage operations
export const uploadBlob = async (
  containerName: string,
  blobName: string,
  data: Buffer | string
): Promise<void> => {
  try {
    if (!blobServiceClient) {
      throw new Error("Blob Storage client not initialized");
    }
    const containerClient = blobServiceClient.getContainerClient(containerName);
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);
    await blockBlobClient.upload(data, Buffer.byteLength(data.toString()));
    logger.info(`Blob ${blobName} uploaded successfully`);
  } catch (error) {
    logger.error(`Error uploading blob ${blobName}:`, error);
    throw error;
  }
};

export const downloadBlob = async (
  containerName: string,
  blobName: string
): Promise<Buffer> => {
  try {
    if (!blobServiceClient) {
      throw new Error("Blob Storage client not initialized");
    }
    const containerClient = blobServiceClient.getContainerClient(containerName);
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);
    const downloadBlockBlobResponse = await blockBlobClient.download();

    if (!downloadBlockBlobResponse.readableStreamBody) {
      throw new Error("No readable stream body");
    }

    const chunks: Buffer[] = [];
    for await (const chunk of downloadBlockBlobResponse.readableStreamBody) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  } catch (error) {
    logger.error(`Error downloading blob ${blobName}:`, error);
    throw error;
  }
};

// Cosmos DB operations
export const getCosmosClient = () => {
  if (!cosmosClient) {
    throw new Error("Cosmos DB client not initialized");
  }
  return cosmosClient;
};

export const createDatabaseAndContainer = async (
  databaseId: string,
  containerId: string,
  partitionKey: string
) => {
  try {
    const { database } = await cosmosClient.databases.createIfNotExists({
      id: databaseId,
    });
    const { container } = await database.containers.createIfNotExists({
      id: containerId,
      partitionKey: { paths: [partitionKey] },
    });
    return { database, container };
  } catch (error) {
    logger.error("Error creating database/container:", error);
    throw error;
  }
};
