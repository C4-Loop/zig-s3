/// Example application demonstrating the S3 client library usage.
///
/// This example shows:
/// - Client initialization with environment-based configuration
/// - Basic bucket operations (create/delete)
/// - Object lifecycle (upload/download/delete)
/// - Listing buckets and objects with pagination
/// - Error handling patterns
/// - Memory management with proper cleanup
///
/// Run with default MinIO configuration:
/// ```bash
/// zig build run
/// ```
///
/// Run with custom AWS configuration:
/// ```bash
/// AWS_ACCESS_KEY_ID=your-key \
/// AWS_SECRET_ACCESS_KEY=your-secret \
/// AWS_REGION=your-region \
/// S3_ENDPOINT=https://your-endpoint \
/// zig build run
/// ```
///
/// Environment Variables:
/// - AWS_ACCESS_KEY_ID: Access key (default: "minioadmin")
/// - AWS_SECRET_ACCESS_KEY: Secret key (default: "minioadmin")
/// - AWS_REGION: AWS region (default: "us-east-1")
/// - S3_ENDPOINT: Custom endpoint URL (default: "http://localhost:9000")
const std = @import("std");
const s3 = @import("s3/lib.zig");
const dotenv = @import("dotenv");

fn loadEnvVars() !s3.S3Config {
    const heapAlloc = std.heap.page_allocator;

    const env_map = try dotenv.getDataFrom(heapAlloc, ".env");

    const access_key = env_map.get("MINIO_ACCESS_KEY") orelse
        return error.MissingAccessKey;
    const secret_key = env_map.get("MINIO_SECRET_KEY") orelse
        return error.MissingSecretKey;
    const endpoint = env_map.get("MINIO_PUBLIC_ENDPOINT") orelse
        return error.MissingEndpoint;

    return s3.S3Config{
        .access_key_id = access_key.?,
        .secret_access_key = secret_key.?,
        .endpoint = endpoint.?,
    };
}

pub fn main() !void {
    // Get allocator
    std.log.info("Initializing GeneralPurposeAllocator", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) {
        std.log.warn("Memory allocator leaked", .{});
    };
    const allocator = gpa.allocator();

    // Initialize S3 client
    std.log.info("Loading environment variables for S3 configuration", .{});
    const config = try loadEnvVars();
    std.log.info("Environment variables loaded successfully", .{});

    std.log.info("Initializing S3 client", .{});
    var client = try s3.S3Client.init(allocator, config);
    defer client.deinit();
    std.log.info("S3 client initialized successfully", .{});

    // List buckets
    std.log.info("Listing S3 buckets", .{});
    const buckets = client.listBuckets() catch |err| {
        std.log.err("Failed to list buckets: {}", .{err});
        return err;
    };
    std.log.info("Buckets listed successfully", .{});
    defer {
        std.log.info("Freeing bucket resources", .{});
        for (buckets) |bucket| {
            allocator.free(bucket.name);
            allocator.free(bucket.creation_date);
        }
        allocator.free(buckets);
        std.log.info("Bucket resources freed", .{});
    }

    // Print bucket information
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.writeAll("\nAvailable buckets:\n");
    for (buckets) |bucket| {
        std.log.info("Bucket found: {s}", .{bucket.name});
        try stdout.print("- {s}\n", .{bucket.name});
    }
    std.log.info("Bucket information printed", .{});
}
