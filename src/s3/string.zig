const std = @import("std");

/// A wrapper type for managing lifetime of UTF-8 string data.
pub const String = union(enum) {
    const Self = @This();

    pub const Context = struct {
        pub fn hash(_: @This(), s: String) u32 {
            return s.hash();
        }
        pub fn eql(_: @This(), a: String, b: String, _: usize) bool {
            return a.eql(b);
        }
    };

    _static: []const u8,
    _borrowed: []const u8,
    _owned: []const u8,

    /// Wrap a static lifetime string.
    pub fn static(comptime data: []const u8) Self {
        return .{ ._static = data };
    }

    /// Borrow a string without taking ownership.
    pub fn borrow(data: []const u8) Self {
        return .{ ._borrowed = data };
    }

    /// Take ownership of string data.
    pub fn take(data: []const u8) Self {
        return .{ ._owned = data };
    }

    /// Use string data to create an owned copy.
    pub fn clone(alloc: std.mem.Allocator, data: []const u8) !Self {
        return .take(try alloc.dupe(u8, data));
    }

    /// Free string data if owned.
    pub fn deinit(self: Self, alloc: std.mem.Allocator) void {
        if (self == ._owned) {
            alloc.free(self._owned);
        }
    }

    /// Duplicate the contents of the string if it's borrowed.
    pub fn dupe(self: *const Self, alloc: std.mem.Allocator) !Self {
        if (self.* == ._static) return self.*;
        return .clone(alloc, self.ref());
    }

    /// Access a read-only reference to the string data.
    pub fn ref(self: *const Self) []const u8 {
        return switch (self.*) {
            inline else => |d| d,
        };
    }

    pub fn hash(self: Self) u32 {
        return @as(u32, @truncate(std.hash.Wyhash.hash(0, self.ref())));
    }

    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.ref(), other.ref());
    }
};
