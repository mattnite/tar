const std = @import("std");

const testing = std.testing;
const Allocator = std.mem.Allocator;

// ustar tar implementation
pub const Header = extern struct {
    name: [100]u8 = std.mem.zeroes([100]u8),
    mode: [7:0]u8 = [_:0]u8{ '0', '0', '0', '0', '6', '6', '6' },
    uid: [7:0]u8 = [_:0]u8{'0'} ** 7,
    gid: [7:0]u8 = [_:0]u8{'0'} ** 7,
    size: [11:0]u8 = [_:0]u8{'0'} ** 11,
    mtime: [11:0]u8 = [_:0]u8{'0'} ** 11,
    checksum: [7:0]u8 = [_:0]u8{'0'} ** 7,
    typeflag: FileType,
    linkname: [100]u8 = std.mem.zeroes([100]u8),
    magic: [5:0]u8 = [_:0]u8{ 'u', 's', 't', 'a', 'r' },
    version: [2]u8 = [_:0]u8{ '0', '0' },
    uname: [31:0]u8 = [_:0]u8{ 'r', 'o', 'o', 't' } ++ std.mem.zeroes([27]u8),
    gname: [31:0]u8 = [_:0]u8{ 'r', 'o', 'o', 't' } ++ std.mem.zeroes([27]u8),
    devmajor: [7:0]u8 = [_:0]u8{'0'} ** 7,
    devminor: [7:0]u8 = [_:0]u8{'0'} ** 7,
    prefix: [155]u8 = std.mem.zeroes([155]u8),
    pad: [12]u8 = std.mem.zeroes([12]u8),

    const Self = @This();

    const FileType = extern enum(u8) {
        regular = '0',
        hard_link = '1',
        symbolic_link = '2',
        character = '3',
        block = '4',
        directory = '5',
        fifo = '6',
        reserved = '7',
        pax_global = 'g',
        extended = 'x',
        _,
    };

    fn fromStat(stat: std.fs.File.Stat, path: []const u8) !Header {
        if (std.mem.indexOf(u8, path, "\\") != null) return error.NeedPosixPath;
        if (std.fs.path.isAbsolute(path)) return error.NeedRelPath;

        var ret = std.mem.zeroes(Header);
        ret = Header{
            .typeflag = switch (stat.kind) {
                .File => .regular,
                .Directory => .directory,
                else => return error.UnsupportedType,
            },
        };

        const name = if (path.len > 100) {
            return error.Todo;
        } else path;

        _ = try std.fmt.bufPrint(&ret.name, "{}", .{name});
        _ = try std.fmt.bufPrint(&ret.size, "{o:0>11}", .{stat.size});
        _ = try std.fmt.bufPrint(&ret.mtime, "{o:0>11}", .{stat.mtime});

        var checksum: usize = 0;
        for (std.mem.asBytes(&ret)) |val| checksum += val;

        _ = try std.fmt.bufPrint(&ret.checksum, "{o:0>7}", .{checksum});

        return ret;
    }

    pub fn isBlank(self: *const Header) bool {
        const block = std.mem.asBytes(self);
        return for (block) |elem| {
            if (elem != 0) break false;
        } else true;
    }
};

test "Header size" {
    testing.expectEqual(512, @sizeOf(Header));
}

pub fn instantiate(
    allocator: *Allocator,
    dir: std.fs.Dir,
    reader: anytype,
    skip_depth: usize,
) !void {
    var count: usize = 0;
    while (true) {
        const header = reader.readStruct(Header) catch |err| {
            return if (err == error.EndOfStream)
                if (count < 2) error.AbrubtEnd else break
            else
                err;
        };

        const block = std.mem.asBytes(&header);
        if (header.isBlank()) {
            count += 1;
            continue;
        } else if (count > 0) {
            return error.Format;
        }

        var size = try std.fmt.parseUnsigned(usize, &header.size, 8);
        const block_size = ((size + 511) / 512) * 512;
        var components = std.ArrayList([]const u8).init(allocator);
        defer components.deinit();

        var path_it = std.mem.tokenize(&header.prefix, "/\x00");
        if (header.prefix[0] != 0) {
            while (path_it.next()) |component| {
                try components.append(component);
            }
        }

        path_it = std.mem.tokenize(&header.name, "/\x00");
        while (path_it.next()) |component| {
            try components.append(component);
        }

        const tmp_path = try std.fs.path.join(allocator, components.items);
        defer allocator.free(tmp_path);

        if (skip_depth >= components.items.len) {
            try reader.skipBytes(block_size, .{});
            continue;
        }

        var i: usize = 0;
        while (i < skip_depth) : (i += 1) {
            _ = components.orderedRemove(0);
        }

        const file_path = try std.fs.path.join(allocator, components.items);
        defer allocator.free(file_path);

        switch (header.typeflag) {
            .directory => try dir.makePath(file_path),
            .pax_global => try reader.skipBytes(512, .{}),
            .regular => {
                const file = try dir.createFile(file_path, .{ .read = true, .truncate = true });
                defer file.close();
                const skip_size = block_size - size;

                var buf: [std.mem.page_size]u8 = undefined;
                while (size > 0) {
                    const buffered = try reader.read(buf[0..std.math.min(size, 512)]);
                    try file.writeAll(buf[0..buffered]);
                    size -= buffered;
                }

                try reader.skipBytes(skip_size, .{});
            },
            else => {},
        }
    }
}

pub fn Archive(comptime Writer: type) type {
    return struct {
        writer: Writer,

        const Self = @This();

        pub fn finish(self: *Self) !void {
            try self.writer.writeByteNTimes(0, 1024);
        }

        /// prefix is a path to prepend subpath with
        pub fn addFile(
            self: *Self,
            allocator: *Allocator,
            root: std.fs.Dir,
            prefix: ?[]const u8,
            subpath: []const u8,
        ) !void {
            const path = if (prefix) |prefix_path|
                try std.fs.path.join(allocator, &[_][]const u8{ prefix_path, subpath })
            else
                subpath;
            defer if (prefix != null) allocator.free(path);

            const subfile = try root.openFile(subpath, .{ .read = true, .write = true });
            defer subfile.close();

            const stat = try subfile.stat();
            const header = try Header.fromStat(stat, path);
            var buf: [std.mem.page_size]u8 = undefined;

            try self.writer.writeAll(std.mem.asBytes(&header));
            var counter = std.io.countingWriter(self.writer);

            while (true) {
                const n = try subfile.reader().read(&buf);
                if (n == 0) break;

                try counter.writer().writeAll(buf[0..n]);
            }

            const padding = 512 - (counter.bytes_written % 512);
            try self.writer.writeByteNTimes(0, padding);
        }

        /// add slice of bytes as file `path`
        pub fn addSlice(self: *Self, slice: []const u8, path: []const u8) !void {
            const stat = std.fs.File.Stat{
                .inode = undefined,
                .size = slice.len,
                .mode = undefined,
                .kind = .File,
                .atime = undefined,
                .mtime = std.time.timestamp(),
                .ctime = undefined,
            };

            var header = try Header.fromStat(stat, path);
            const padding = 512 - (slice.len % 512);
            try self.writer.writeAll(std.mem.asBytes(&header));
            try self.writer.writeAll(slice);
            try self.writer.writeByteNTimes(0, padding);
        }
    };
}

pub fn archive(writer: anytype) Archive(@TypeOf(writer)) {
    return .{ .writer = writer };
}
