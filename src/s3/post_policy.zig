const std = @import("std");
const Allocator = std.mem.Allocator;

const String = @import("string.zig").String;
const signer = @import("client/auth/signer.zig");
const UtcDateTime = @import("client/auth/time.zig").UtcDateTime;
const S3Config = @import("client/implementation.zig").S3Config;

const Self = @This();

pub const ConditionMatch = union(enum) {
    /// The form field value must match the value specified.
    exact: String,
    /// The value must start with the specified value.
    @"starts-with": String,
    /// For form fields that accept an upper and lower limit range (in bytes).
    @"content-length-range": struct { min: u64, max: u64 },

    fn deinit(self: *ConditionMatch, alloc: Allocator) void {
        switch (self.*) {
            .exact => |e| e.deinit(alloc),
            .@"starts-with" => |sw| sw.deinit(alloc),
            .@"content-length-range" => {},
        }
    }

    fn jsonWrite(self: *const ConditionMatch, jws: anytype, name: []const u8) !void {
        switch (self.*) {
            .exact => |e| {
                try jws.beginObject();
                try jws.objectField(name);
                try jws.write(e.ref());
                try jws.endObject();
            },
            .@"starts-with" => |sw| {
                try jws.beginArray();
                try jws.write("starts-with");
                try jws.print("${s}", .{name});
                try jws.write(sw.ref());
                try jws.endArray();
            },
            .@"content-length-range" => |r| {
                try jws.beginArray();
                try jws.write("content-length-range");
                try jws.write(r.min);
                try jws.write(r.max);
                try jws.endArray();
            },
        }
    }
};

pub const ConditionVariable = union(enum) {
    /// Specifies the ACL value that must be used in the form submission.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    acl,
    /// Specifies the acceptable bucket name.
    /// This condition supports `exact` matching condition match type.
    bucket,
    /// The minimum and maximum allowable size for the uploaded content.
    /// This condition supports `content-length-range` condition match type.
    @"content-length-range",
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    @"Cache-Control",
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    @"Content-Type",
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    @"Content-Disposition",
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    @"Content-Encoding",
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    Expires,
    /// The acceptable key name or a prefix of the uploaded object.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    key,
    /// The URL to which the client is redirected upon successful upload.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    @"success-action-redirect",
    /// The URL to which the client is redirected upon successful upload.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    redirect,

    /// The signing algorithm that must be used during signature calculation. For AWS Signature Version 4, the value is AWS4-HMAC-SHA256.
    /// This condition supports `exact` matching.
    @"x-amz-algorithm",
    /// The credentials that you used to calculate the signature.
    @"x-amz-credential",
    /// The date value specified in the ISO8601 formatted string. For example, 20130728T000000Z.
    /// The date must be same that you used in creating the signing key for signature calculation.
    /// This condition supports `exact` matching.
    @"x-amz-date",
    /// Amazon DevPay security token.
    @"x-amz-security-token",

    /// User-specified metadata.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    meta: String,
    /// The storage class to use for storing the object.
    /// This condition supports `exact` matching.
    @"x-amz-storage-class",
    /// If the bucket is configured as a website, this field redirects requests for this object to another object in the same bucket or to an external URL.
    /// This condition supports `exact` matching.
    @"x-amz-website-redirect-location",
    /// Indicates the algorithm used to create the checksum for the object.
    /// This condition supports `exact` matching.
    @"x-amz-checksum-algorithm": ChecksumAlgorithm,

    fn deinit(self: *ConditionVariable, alloc: Allocator) void {
        switch (self.*) {
            .meta => |m| m.deinit(alloc),
            else => {},
        }
    }

    fn equals(self: ConditionVariable, other: ConditionVariable) bool {
        return switch (self) {
            .meta => other == .meta and self.meta.eql(other.meta),
            else => std.meta.eql(self, other),
        };
    }
};

pub const ChecksumAlgorithm = enum {
    /// Specifies the base64-encoded, 32-bit CRC32 checksum of the object.
    CRC32,
    /// Specifies the base64-encoded, 32-bit CRC32C checksum of the object.
    CRC32C,
    /// Specifies the base64-encoded, 160-bit SHA-1 digest of the object.
    SHA1,
    /// Specifies the base64-encoded, 256-bit SHA-256 digest of the object.
    SHA256,

    fn name(self: ChecksumAlgorithm) String {
        return switch (self) {
            .CRC32 => .static("x-amz-checksum-crc32"),
            .CRC32C => .static("x-amz-checksum-crc32c"),
            .SHA1 => .static("x-amz-checksum-sha1"),
            .SHA256 => .static("x-amz-checksum-sha256"),
        };
    }
};

pub const Condition = struct {
    variable: ConditionVariable,
    match: ConditionMatch,

    fn deinit(self: *Condition, alloc: Allocator) void {
        self.variable.deinit(alloc);
        self.match.deinit(alloc);
    }

    pub fn jsonStringify(self: *const Condition, jws: anytype) !void {
        switch (self.variable) {
            .meta => |meta| try self.match.jsonWrite(jws, meta.ref()),
            .@"x-amz-checksum-algorithm" => |algo| {
                const algoMatch: ConditionMatch = .{ .exact = .borrow(@tagName(algo)) };
                try algoMatch.jsonWrite(jws, "x-amz-checksum-algorithm");
                try self.match.jsonWrite(jws, algo.name().ref());
            },
            else => try self.match.jsonWrite(jws, @tagName(self.variable)),
        }
    }

    pub fn formWrite(self: *const Condition, form_data: *FormData) !void {
        const val: String = switch (self.match) {
            .exact => |e| try e.dupe(form_data.allocator),
            .@"starts-with" => |sw| try sw.dupe(form_data.allocator),
            else => return,
        };
        errdefer val.deinit(form_data.allocator);

        switch (self.variable) {
            .meta => |meta| try form_data.put(try meta.dupe(form_data.allocator), val),
            .@"x-amz-checksum-algorithm" => |algo| {
                try form_data.put(.borrow(@tagName(self.variable)), .borrow(@tagName(algo)));
                try form_data.put(algo.name(), val);
            },
            else => try form_data.put(.borrow(@tagName(self.variable)), val),
        }
    }
};

const FormData = std.ArrayHashMap(String, String, String.Context, true);

_alloc: Allocator,

/// Unix timestamp (in seconds)
expiration: i64,

/// List of conditions in the policy
conditions: std.ArrayList(Condition) = .empty,

/// TODO
form_data: FormData,

/// Create a new POST Policy that expires at the Unix timestamp (in seconds).
pub fn expires_at(alloc: Allocator, unix_timestamp_secs: i64) Self {
    return .{
        ._alloc = alloc,
        .expiration = unix_timestamp_secs,
        .form_data = .init(alloc),
    };
}

/// Create a POST Policy that expires in a certain number of seconds from now.
pub fn expires_in(alloc: Allocator, seconds: i64) Self {
    return .expires_at(alloc, std.time.timestamp() + seconds);
}

pub fn deinit(self: *Self) void {
    for (self.conditions.items) |*cond| {
        cond.deinit(self._alloc);
    }
    self.conditions.deinit(self._alloc);

    var it = self.form_data.iterator();
    while (it.next()) |v| {
        v.key_ptr.deinit(self._alloc);
        v.value_ptr.deinit(self._alloc);
    }
    self.form_data.deinit();
}

/// Add custom condition to the policy.
/// Takes ownership of the condition.
pub fn add(self: *Self, cond: Condition) !void {
    try cond.formWrite(&self.form_data);
    try self.conditions.append(self._alloc, cond);
}

/// Determine whether the policy includes the condition variable.
pub fn has(self: *const Self, cv: ConditionVariable) bool {
    for (self.conditions.items) |c| {
        if (c.variable.equals(cv)) {
            return true;
        }
    }
    return false;
}

/// Set bucket name
pub fn setBucket(self: *Self, bucket: String) !void {
    return self.add(.{ .variable = .bucket, .match = .{ .exact = bucket } });
}

/// Set object name
pub fn setKey(self: *Self, key: String) !void {
    return self.add(.{ .variable = .key, .match = .{ .exact = key } });
}

/// Set object name prefix
pub fn setKeyStartsWith(self: *Self, prefix: String) !void {
    return self.add(.{ .variable = .key, .match = .{ .starts_with = prefix } });
}

/// Set content type
pub fn setContentType(self: *Self, key: String) !void {
    return self.add(.{ .variable = .@"Content-Type", .match = .{ .exact = key } });
}

/// Set content type prefix
pub fn setContentTypeStartsWith(self: *Self, prefix: String) !void {
    return self.add(.{ .variable = .@"Content-Type", .match = .{ .starts_with = prefix } });
}

/// Set content disposition
pub fn setContentDisposition(self: *Self, key: String) !void {
    return self.add(.{ .variable = .@"Content-Disposition", .match = .{ .exact = key } });
}

/// Set content length range
pub fn setContentLengthRange(self: *Self, min: u64, max: u64) !void {
    return self.add(.{ .variable = .@"content-length-range", .match = .{ .@"content-length-range" = .{ .min = min, .max = max } } });
}

pub fn jsonStringify(self: *const Self, jws: anytype) !void {
    try jws.beginObject();
    try jws.objectField("expiration");
    try jws.write(UtcDateTime.init(self.expiration));
    try jws.objectField("conditions");
    try jws.write(self.conditions.items);
    try jws.endObject();
}

pub const PresignedPostPolicy = struct {
    _alloc: Allocator,
    post_url: []const u8,
    form_data: FormData,

    pub fn deinit(self: *PresignedPostPolicy) void {
        self._alloc.free(self.post_url);
        var it = self.form_data.iterator();
        while (it.next()) |v| {
            v.key_ptr.deinit(self._alloc);
            v.value_ptr.deinit(self._alloc);
        }
        self.form_data.deinit();
    }
};

pub fn presign(self: *Self, config: *const S3Config) !PresignedPostPolicy {
    const dt = UtcDateTime.now();
    const date_str = try dt.formatAmzDate(self._alloc);
    defer self._alloc.free(date_str);

    if (!self.has(.@"x-amz-date")) {
        try self.add(.{ .variable = .@"x-amz-date", .match = .{ .exact = .take(try dt.formatAmz(self._alloc)) } });
    }
    if (!self.has(.@"x-amz-algorithm")) {
        try self.add(.{ .variable = .@"x-amz-algorithm", .match = .{ .exact = .static("AWS4-HMAC-SHA256") } });
    }
    if (!self.has(.@"x-amz-credential")) {
        const cred: []const u8 = try std.fmt.allocPrint(
            self._alloc,
            "{s}/{s}/{s}/s3/aws4_request",
            .{ config.access_key_id, date_str, config.region },
        );
        try self.add(.{ .variable = .@"x-amz-credential", .match = .{ .exact = .take(cred) } });
    }

    const policy: String = base64: {
        const policy_json = try std.json.Stringify.valueAlloc(self._alloc, self, .{});
        defer self._alloc.free(policy_json);
        var aw: std.io.Writer.Allocating = .init(self._alloc);
        defer aw.deinit();
        try std.base64.standard.Encoder.encodeWriter(&aw.writer, policy_json);
        break :base64 String.take(try aw.toOwnedSlice());
    };
    errdefer policy.deinit(self._alloc);

    // Calculate signature
    const signature: String = sig: {
        const signing_key = try signer.deriveSigningKey(
            self._alloc,
            config.secret_access_key,
            date_str,
            config.region,
            "s3",
        );
        defer self._alloc.free(signing_key);

        break :sig String.take(try signer.calculateSignature(self._alloc, signing_key, policy.ref()));
    };
    errdefer signature.deinit(self._alloc);

    // Take ownership of the policy form data
    var form_data: FormData = self.form_data;
    self.form_data = .init(self._alloc);
    errdefer form_data.deinit();

    // Add final entries into form data
    try form_data.put(.static("policy"), policy);
    try form_data.put(.static("x-amz-signature"), signature);

    var it = form_data.iterator();
    while (it.next()) |e| {
        std.debug.print("{s} -> {s}\n", .{ e.key_ptr.ref(), e.value_ptr.ref() });
    }

    // TODO calculate the post url

    return .{
        ._alloc = self._alloc,
        .post_url = "",
        .form_data = form_data,
    };
}
