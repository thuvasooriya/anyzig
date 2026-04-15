const std = @import("std");
const zig = @import("zig");
const LockFile = @import("LockFile.zig");
const anyzig = @import("root");

pub fn init(path: []const u8) !void {
    std.fs.cwd().makePath(path) catch |err| switch (err) {
        error.NotDir => {
            try std.fs.cwd().deleteFile(path);
            try std.fs.cwd().makePath(path);
        },
        else => |e| return e,
    };
}

const Lock = struct {
    lockfile: LockFile,
    hashfile_path: []const u8,
    pub fn init(arena: std.mem.Allocator, hashstore_path: []const u8, name: []const u8) !Lock {
        const lockfile_basename = std.fmt.allocPrint(arena, "{s}.lock", .{name}) catch |e| oom(e);
        const lockfile_path = std.fs.path.join(arena, &.{ hashstore_path, lockfile_basename }) catch |e| oom(e);
        var lockfile = try LockFile.lock(lockfile_path);
        errdefer lockfile.unlock();
        return .{
            .lockfile = lockfile,
            .hashfile_path = std.fs.path.join(arena, &.{ hashstore_path, name }) catch |e| oom(e),
        };
    }
    pub fn unlock(self: *Lock) void {
        // no need to free anything allocated by the arena
        self.lockfile.unlock();
    }
};

pub fn find(hashstore_path: []const u8, name: []const u8) !?zig.Package.Hash {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var lock = try Lock.init(arena, hashstore_path, name);
    defer lock.unlock();

    const full_content = blk: {
        const file = std.fs.cwd().openFile(lock.hashfile_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => |e| return e,
        };
        defer file.close();
        break :blk try file.readToEndAlloc(arena, std.math.maxInt(usize));
    };
    defer arena.free(full_content);
    const hash_bytes = std.mem.trim(u8, full_content, &std.ascii.whitespace);
    if (hash_bytes.len > zig.Package.Hash.max_len) {
        anyzig.log.warn(
            "{s}: file is too big (max is {})",
            .{ lock.hashfile_path, zig.Package.Hash.max_len },
        );
        try std.fs.cwd().deleteFile(lock.hashfile_path);
        return null;
    }
    return zig.Package.Hash.fromSlice(hash_bytes);
}

pub fn save(hashstore_path: []const u8, name: []const u8, content: []const u8) !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    var lock = try Lock.init(arena, hashstore_path, name);
    defer lock.unlock();
    // no need to write to a temporary file and rename since we have a lock file
    const store_file = try std.fs.cwd().createFile(lock.hashfile_path, .{});
    defer store_file.close();
    try store_file.deprecatedWriter().writeAll(content);
}

pub fn delete(hashstore_path: []const u8, name: []const u8) !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    var lock = try Lock.init(arena, hashstore_path, name);
    defer lock.unlock();
    std.fs.cwd().deleteFile(lock.hashfile_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };
}

const ReverseLookup = std.AutoHashMapUnmanaged(
    zig.Package.Hash,
    std.ArrayListUnmanaged(anyzig.SemanticVersion),
);
pub fn allocReverseLookup(
    hashstore_path: []const u8,
    allocator: std.mem.Allocator,
) !ReverseLookup {
    var dir = try std.fs.cwd().makeOpenPath(hashstore_path, .{ .iterate = true });
    defer dir.close();
    var map: ReverseLookup = .{};
    var it = dir.iterate();
    const prefix = anyzig.exe_str ++ "-";
    const compat_prefix = anyzig.exe_str ++ "-compat-";
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, prefix)) continue;
        // Skip compat mapping files (e.g., zls-compat-0.15.2)
        if (std.mem.startsWith(u8, entry.name, compat_prefix)) continue;
        const version_str = entry.name[prefix.len..];
        const entry_version = anyzig.SemanticVersion.parse(version_str) orelse std.debug.panic(
            "entry '{s}' contains an invalid version '{s}'",
            .{ entry.name, version_str },
        );
        const hash = (try find(hashstore_path, entry.name)) orelse std.debug.panic(
            "hashstore entry '{s}' disappeared while iterating?",
            .{entry.name},
        );
        const map_entry = map.getOrPut(allocator, hash) catch |e| oom(e);
        if (!map_entry.found_existing) {
            map_entry.value_ptr.* = .{};
        }
        map_entry.value_ptr.append(allocator, entry_version) catch |e| oom(e);
    }
    return map;
}

// ZLS compatibility mapping API
// Stores version-string mappings with optional TTL support.
// Uses the same hashstore directory and locking mechanism.
const compat_ttl_seconds: i64 = 7 * 24 * 60 * 60; // 7 days

pub fn saveCompat(hashstore_path: []const u8, name: []const u8, version_str: []const u8) !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    var lock = try Lock.init(arena, hashstore_path, name);
    defer lock.unlock();
    const store_file = try std.fs.cwd().createFile(lock.hashfile_path, .{});
    defer store_file.close();
    const timestamp = std.time.timestamp();
    try store_file.deprecatedWriter().print("{d}\n{s}\n", .{ timestamp, version_str });
}

pub const CompatResult = struct {
    version_str: []const u8,
    is_expired: bool,
};

pub fn findCompat(hashstore_path: []const u8, name: []const u8, arena: std.mem.Allocator) !?CompatResult {
    var lock_arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer lock_arena_instance.deinit();
    const lock_arena = lock_arena_instance.allocator();

    var lock = try Lock.init(lock_arena, hashstore_path, name);
    defer lock.unlock();

    const full_content = blk: {
        const file = std.fs.cwd().openFile(lock.hashfile_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => |e| return e,
        };
        defer file.close();
        break :blk try file.readToEndAlloc(arena, 1024);
    };
    const trimmed = std.mem.trim(u8, full_content, &std.ascii.whitespace);
    // Format: "{timestamp}\n{version_str}"
    if (std.mem.indexOfScalar(u8, trimmed, '\n')) |newline_pos| {
        const timestamp_str = trimmed[0..newline_pos];
        const version_str = trimmed[newline_pos + 1 ..];
        const stored_timestamp = std.fmt.parseInt(i64, timestamp_str, 10) catch {
            // Corrupted file, treat as not found
            arena.free(full_content);
            return null;
        };
        const now = std.time.timestamp();
        const is_expired = (now - stored_timestamp) > compat_ttl_seconds;
        return .{
            .version_str = version_str,
            .is_expired = is_expired,
        };
    }
    // Legacy format (no timestamp) - treat as expired so it gets refreshed
    return .{
        .version_str = trimmed,
        .is_expired = true,
    };
}

pub fn deleteCompat(hashstore_path: []const u8, name: []const u8) !void {
    return delete(hashstore_path, name);
}

pub fn oom(e: error{OutOfMemory}) noreturn {
    @panic(@errorName(e));
}
