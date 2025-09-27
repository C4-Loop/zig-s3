const std = @import("std");
const Allocator = std.mem.Allocator;

const S3Config = @import("client/implementation.zig").S3Config;

const Self = @This();

pub const ConditionMatch = union(enum) {
    /// The form field value must match the value specified.
    exact: []const u8,
    /// The value must start with the specified value.
    starts_with: []const u8,
    /// For form fields that accept an upper and lower limit range (in bytes).
    content_length_range: struct { min: u64, max: u64 },

    fn clone(self: *const ConditionMatch, alloc: Allocator) !ConditionMatch {
        return switch (self.*) {
            .exact => |e| .{ .exact = try alloc.dupe(u8, e) },
            .starts_with => |sw| .{ .starts_with = try alloc.dupe(u8, sw) },
            .content_length_range => self.*,
        };
    }

    fn deinit(self: *ConditionMatch, alloc: Allocator) void {
        switch (self.*) {
            .exact => |e| alloc.free(e),
            .starts_with => |sw| alloc.free(sw),
            .content_length_range => {},
        }
    }
};

pub const ConditionVariable = enum {
    /// Specifies the ACL value that must be used in the form submission.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    acl,
    /// Specifies the acceptable bucket name.
    /// This condition supports exact matching condition match type.
    bucket,
    /// The minimum and maximum allowable size for the uploaded content.
    /// This condition supports `content-length-range` condition match type.
    content_length_range,
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    cache_control,
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    content_type,
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    content_disposition,
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    content_encoding,
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    expires,
    /// The acceptable key name or a prefix of the uploaded object.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    key,
};

pub const Condition = struct {
    variable: ConditionVariable,
    match: ConditionMatch,

    fn deinit(self: *Condition, alloc: Allocator) void {
        self.match.deinit(alloc);
    }
};

_alloc: Allocator,

/// Unix timestamp (in seconds)
expiration: i64,

// List of conditions in the policy
conditions: std.ArrayList(Condition) = .empty,

/// Create a new POST Policy that expires at the Unix timestamp (in seconds).
pub fn expires_at(alloc: Allocator, unix_timestamp_secs: i64) Self {
    return .{ ._alloc = alloc, .expiration = unix_timestamp_secs };
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
}

/// Add custom condition to the policy
pub fn add(self: *Self, cond: Condition) !void {
    const copy: Condition = .{
        .variable = cond.variable,
        .match = try cond.match.clone(self._alloc),
    };
    try self.conditions.append(self._alloc, copy);
}

/// Set bucket name
pub fn setBucket(self: *Self, bucket: []const u8) !void {
    return self.add(.{ .variable = .bucket, .match = .{ .exact = bucket } });
}

/// Set object name
pub fn setKey(self: *Self, key: []const u8) !void {
    return self.add(.{ .variable = .key, .match = .{ .exact = key } });
}

/// Set object name prefix
pub fn setKeyStartsWith(self: *Self, prefix: []const u8) !void {
    return self.add(.{ .variable = .key, .match = .{ .starts_with = prefix } });
}

/// Set content type
pub fn setContentType(self: *Self, key: []const u8) !void {
    return self.add(.{ .variable = .content_type, .match = .{ .exact = key } });
}

/// Set content type prefix
pub fn setContentTypeStartsWith(self: *Self, prefix: []const u8) !void {
    return self.add(.{ .variable = .content_type, .match = .{ .starts_with = prefix } });
}

/// Set content disposition
pub fn setContentDisposition(self: *Self, key: []const u8) !void {
    return self.add(.{ .variable = .content_disposition, .match = .{ .exact = key } });
}

/// Set content length range
pub fn setContentLengthRange(self: *Self, min: i64, max: i64) !void {
    return self.add(.{ .variable = .content_length_range, .match = .{ .content_length_range = .{ .min = min, .max = max } } });
}

pub const PresignedPostPolicy = struct {
    _alloc: Allocator,
    url: []const u8,
    form_data: std.StringArrayHashMap([]const u8),

    pub fn deinit(self: *PresignedPostPolicy) void {
        self._alloc.free(self.url);
        self._alloc.free(self.form_data);
    }
};

pub fn presign(self: *Self, config: *const S3Config) PresignedPostPolicy {
    // TODO
    _ = config;
    return .{
        ._alloc = self._alloc,
    };
}
