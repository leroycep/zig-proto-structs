const std = @import("std");

pub fn encode(allocator: *std.mem.Allocator, value: anytype) ![]u8 {
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    return try encoder.encodeOwned(value);
}

pub const Encoder = struct {
    bytes: std.ArrayList(u8) = undefined,
    pointers_encoded: std.AutoHashMap(usize, u32) = undefined,

    pub const Error = error{} || std.mem.Allocator.Error;

    pub fn init(allocator: *std.mem.Allocator) @This() {
        return @This(){
            .bytes = std.ArrayList(u8).init(allocator),
            .pointers_encoded = std.AutoHashMap(usize, u32).init(allocator),
        };
    }

    pub fn deinit(this: *@This()) void {
        this.bytes.deinit();
        this.pointers_encoded.deinit();
    }

    pub fn encode(this: *@This(), value: anytype) ![]u8 {
        this.bytes.shrinkRetainingCapacity(0);
        this.pointers_encoded.clearRetainingCapacity();

        const root_byte_len = space_required(@TypeOf(value));
        const root_space = try this.reserve_space(root_byte_len);
        try this.encode_value(value, root_space);

        return this.bytes.items;
    }

    pub fn encodeOwned(this: *@This(), value: anytype) ![]u8 {
        _ = try this.encode(value);
        defer this.pointers_encoded.clearRetainingCapacity();

        return this.bytes.toOwnedSlice();
    }

    const Space = struct {
        ptr: u32,
        len: u32,
    };

    fn reserve_space(this: *@This(), num_bytes: u32) !Space {
        if (num_bytes == 0) return Space{ .ptr = 0, .len = 0 };
        const offset = this.bytes.items.len;
        try this.bytes.appendNTimes(0, num_bytes);
        return Space{ .ptr = @intCast(u32, offset), .len = num_bytes };
    }

    fn space_to_slice(this: *@This(), space: Space) []u8 {
        return this.bytes.items[space.ptr .. space.ptr + space.len];
    }

    fn encode_value(this: *@This(), value: anytype, space: Space) Error!void {
        const T = @TypeOf(value);
        //std.log.warn("encode_value({}) space = {}", .{ T, space });
        switch (@typeInfo(T)) {
            .Bool => {
                var slice = this.space_to_slice(space);
                slice[0] = @boolToInt(value);
            },
            .Int => |info| {
                var slice = this.space_to_slice(space);
                std.mem.writeIntLittle(T, slice[0..@sizeOf(T)], value);
            },
            .Pointer => |info| switch (info.size) {
                .One => {
                    const gop = try this.pointers_encoded.getOrPut(@ptrToInt(value));

                    const child_size = space_required(info.child);
                    //std.log.warn("encode_value({}) child_size = {}", .{ T, child_size });
                    if (!gop.found_existing) {
                        const child_space = try this.reserve_space(child_size);

                        gop.entry.value = child_space.ptr;

                        try this.encode_value(value.*, child_space);
                    }
                    var slice = this.space_to_slice(space);
                    std.mem.writeIntLittle(u32, slice[0..4], gop.entry.value);
                },
                .Slice => {
                    const child_size = space_required(info.child);
                    const len = @intCast(u32, value.len);
                    const children_space = try this.reserve_space(child_size * len);
                    // Write offset + len
                    {
                        var slice = this.space_to_slice(space);
                        std.mem.writeIntLittle(u32, slice[0..4], children_space.ptr);
                        std.mem.writeIntLittle(u32, slice[4..8], len);
                    }
                    //std.log.warn("encode_value({}) children_space = {}, space_bytes = {}", .{ T, children_space, fmtSliceHexSpaced(this.bytes.items) });
                    // Write child values
                    {
                        for (value) |child, idx| {
                            const child_space = Space{ .ptr = children_space.ptr + @intCast(u32, idx) * child_size, .len = child_size };
                            try this.encode_value(child, child_space);
                        }
                    }
                },
                else => |s| @compileError("Pointer size " ++ s ++ " is not supported"),
            },
            .Struct => |info| {
                comptime var offset: u32 = 0;
                inline for (info.fields) |field| {
                    const field_len = comptime space_required(field.field_type);
                    const field_space = Space{
                        .ptr = space.ptr + offset,
                        .len = field_len,
                    };
                    try this.encode_value(@field(value, field.name), field_space);
                    offset += field_len;
                }
            },
            .Optional => |info| {
                var slice = this.space_to_slice(space);
                if (value) |not_null| {
                    slice[0] = 1;
                    try this.encode_value(not_null, .{
                        .ptr = space.ptr + 1,
                        .len = space.len - 1,
                    });
                } else {
                    slice[0] = 0;
                }
            },
            .Array => |info| {
                const child_size = space_required(info.child);
                for (value) |child, idx| {
                    const child_space = Space{ .ptr = space.ptr + @intCast(u32, idx) * child_size, .len = child_size };
                    try this.encode_value(child, child_space);
                }
            },
            .Enum => |info| try this.encode_value(@enumToInt(value), space),
            .Union => |info| {
                const tag = @as(info.tag_type.?, value);
                const tag_space = space_required(@TypeOf(tag));
                try this.encode_value(tag, .{ .ptr = space.ptr, .len = tag_space });
                inline for (info.fields) |f| {
                    if (tag == @field(info.tag_type.?, f.name)) {
                        return try this.encode_value(@field(value, f.name), .{ .ptr = space.ptr + tag_space, .len = space.len - tag_space });
                    }
                }
            },
            else => |t| @compileError("Type " ++ std.meta.tagName(t) ++ " is not supported"),
        }
    }
};

fn space_required(comptime T: type) u32 {
    switch (@typeInfo(T)) {
        .Bool => return 1,
        .Int => |info| {
            if (info.bits % 8 != 0) {
                @compileError("Cannot use int " ++ @typeName(T) ++ "; integer bits must be a multiple of 8");
            }
            return @sizeOf(T);
        },
        .Pointer => |info| switch (info.size) {
            .One => return 4, // offset
            .Slice => return 4 + 4, // offset + len
            else => |s| @compileError("Pointer size " ++ s ++ " is not supported"),
        },
        .Struct => |info| {
            comptime var size: u32 = 0;
            inline for (info.fields) |field| {
                // TODO: Alignment?
                size += comptime space_required(field.field_type);
            }
            return size;
        },
        .Optional => |info| {
            return 1 + space_required(info.child);
        },
        .Array => |info| {
            return info.len * space_required(info.child);
        },
        .Enum => |info| {
            if (@bitSizeOf(info.tag_type) % 8 != 0) {
                @compileError("Cannot use enum " ++ @typeName(T) ++ "; tag type must be a multiple of 8");
            }
            return @sizeOf(info.tag_type);
        },
        .Union => |info| {
            comptime var size: u32 = 0;
            inline for (info.fields) |field| {
                // TODO: Alignment?
                const child_size = comptime space_required(field.field_type);
                if (size < child_size) {
                    size = child_size;
                }
            }
            return size + comptime space_required(info.tag_type.?);
        },
        else => |t| @compileError("Type " ++ std.meta.tagName(t) ++ " is not supported"),
    }
}

pub fn Decoder(comptime _T: type) type {
    return struct {
        bytes: []const u8,
        ptr: u32,

        const T = _T;

        pub fn fromBytes(bytes: []const u8) ?@This() {
            if (space_required(T) > bytes.len) {
                return null;
            }
            return @This(){
                .bytes = bytes,
                .ptr = 0,
            };
        }

        fn child_type() type {
            switch (@typeInfo(T)) {
                .Pointer => |info| {
                    return info.child;
                },
                else => |t| @compileError(std.meta.tagName(t) ++ " has no child type"),
            }
        }

        pub fn element(this: @This(), idx: u32) Decoder(child_type()) {
            return this.tryElement(idx) catch unreachable;
        }

        pub fn tryElement(this: @This(), idx: u32) !Decoder(child_type()) {
            switch (@typeInfo(T)) {
                .Pointer => |info| {
                    if (info.size != .Slice) {
                        @compileError("Cannot access pointer size " ++ std.meta.tagName(info.size) ++ " as an array. Only slices are supported.");
                    }
                    const length = std.mem.readIntLittle(u32, this.bytes[this.ptr..][4..8]);
                    if (idx > length) {
                        return error.OutOfBounds;
                    }
                    const ptr = std.mem.readIntLittle(u32, this.bytes[this.ptr..][0..4]);
                    const child_size = space_required(child_type());
                    const child_ptr = ptr + idx * child_size;
                    if (child_ptr + child_size > this.bytes.len) {
                        return error.OutOfBounds;
                    }
                    return Decoder(child_type()){ .bytes = this.bytes, .ptr = child_ptr };
                },
                else => |t| @compileError("Cannot access type " ++ std.meta.tagName(t) ++ " as an array"),
            }
        }

        pub fn len(this: @This()) u32 {
            switch (@typeInfo(T)) {
                .Pointer => |info| {
                    if (info.size != .Slice) {
                        @compileError("Cannot access pointer size " ++ std.meta.tagName(info.size) ++ " as an array. Only slices are supported.");
                    }
                    return std.mem.readIntLittle(u32, this.bytes[this.ptr..][4..8]);
                },
                else => |t| @compileError("Cannot access type " ++ std.meta.tagName(t) ++ " as an array"),
            }
        }

        pub fn deref(this: @This()) Decoder(child_type()) {
            return this.tryDeref() catch unreachable;
        }

        pub fn tryDeref(this: @This()) !Decoder(child_type()) {
            switch (@typeInfo(T)) {
                .Pointer => |info| {
                    if (info.size != .One) {
                        @compileError("Cannot access pointer size " ++ std.meta.tagName(info.size) ++ " as a pointer.");
                    }
                    const ptr = std.mem.readIntLittle(u32, this.bytes[this.ptr..][0..4]);
                    const child_size = space_required(child_type());
                    if (ptr + child_size > this.bytes.len) {
                        // TODO: Consider returning an error instead?
                        return error.OutOfBounds;
                    }
                    return Decoder(child_type()){ .bytes = this.bytes, .ptr = ptr };
                },
                else => |t| @compileError("Cannot access type " ++ std.meta.tagName(t) ++ " as an array"),
            }
        }

        pub fn asSlice(this: @This()) []const child_type() {
            return this.tryAsSlice() catch unreachable;
        }

        pub fn tryAsSlice(this: @This()) ![]const child_type() {
            const ti = @typeInfo(T);
            if (ti != .Pointer or ti.Pointer.size != .Slice or ti.Pointer.child != u8) {
                @compileError("Cannot get " ++ @typeName(T) ++ " as a slice.");
            }
            const ptr = std.mem.readIntLittle(u32, this.bytes[this.ptr..][0..4]);
            const length = std.mem.readIntLittle(u32, this.bytes[this.ptr..][4..8]);
            const child_size = space_required(child_type());
            if (ptr > this.bytes.len or ptr + length * child_size > this.bytes.len) {
                return error.OutOfBounds;
            }
            return this.bytes[ptr .. ptr + length];
        }

        fn field_type(comptime field_name: []const u8) type {
            switch (@typeInfo(T)) {
                .Struct => |info| {
                    inline for (info.fields) |child_field| {
                        if (std.mem.eql(u8, field_name, child_field.name)) {
                            return child_field.field_type;
                        }
                    }
                    @compileError("Unknown field " ++ field_name ++ " in struct " ++ @typeName(T));
                },
                else => |t| @compileError(std.meta.tagName(t) ++ " has no child type"),
            }
        }

        pub fn field(this: @This(), comptime field_name: []const u8) Decoder(field_type(field_name)) {
            return this.tryField(field_name) catch unreachable;
        }

        pub fn tryField(this: @This(), comptime field_name: []const u8) !Decoder(field_type(field_name)) {
            switch (@typeInfo(T)) {
                .Struct => |info| {
                    comptime var offset: u32 = 0;
                    inline for (info.fields) |child_field| {
                        const field_len = comptime space_required(child_field.field_type);
                        if (comptime std.mem.eql(u8, field_name, child_field.name)) {
                            if (this.ptr + offset + field_len > this.bytes.len) {
                                return error.OutOfBounds;
                            }
                            return Decoder(child_field.field_type){
                                .bytes = this.bytes,
                                .ptr = this.ptr + offset,
                            };
                        }
                        offset += field_len;
                    }
                    @compileError("Unknown field " ++ field_name ++ " in struct " ++ @typeName(T));
                },
                else => |t| @compileError("Cannot access type " ++ @typeName(T) ++ " as a struct"),
            }
        }

        pub fn toValue(this: @This()) T {
            switch (@typeInfo(T)) {
                .Bool => {
                    return this.bytes[this.ptr] != 0;
                },
                .Int => {
                    const size = @sizeOf(T);
                    return std.mem.readIntLittle(T, this.bytes[this.ptr..][0..size]);
                },
                .Optional => |info| {
                    if (this.bytes[this.ptr] == 1) {
                        return (Decoder(info.child){
                            .bytes = this.bytes,
                            .ptr = this.ptr + 1,
                        }).toValue();
                    } else {
                        return null;
                    }
                },
                .Array => |info| {
                    var val: [info.len]info.child = undefined;

                    const size = space_required(info.child);
                    var i: u32 = 0;
                    while (i < info.len) : (i += 1) {
                        val[i] = (Decoder(info.child){
                            .bytes = this.bytes,
                            .ptr = this.ptr + i * size,
                        }).toValue();
                    }

                    return val;
                },
                else => @compileError("Cannot convert " ++ @typeName(T) ++ " to a value"),
            }
        }

        pub fn tryToValue(this: @This()) !T {
            switch (@typeInfo(T)) {
                .Bool, .Int, .Optional, .Array => return this.toValue(),
                .Enum => |info| {
                    std.debug.assert(info.is_exhaustive);
                    const size = comptime space_required(T);
                    const tag_int = std.mem.readIntLittle(info.tag_type, this.bytes[this.ptr..][0..size]);
                    return try std.meta.intToEnum(T, tag_int);
                },
                else => @compileError("Cannot convert " ++ @typeName(T) ++ " to a value"),
            }
        }

        fn decoder_union(comptime union_type: type) type {
            const ti = @typeInfo(T).Union;

            comptime var decoder_union_fields: [ti.fields.len]std.builtin.TypeInfo.UnionField = undefined;
            inline for (ti.fields) |union_field, idx| {
                decoder_union_fields[idx] = .{
                    .name = union_field.name,
                    .field_type = Decoder(union_field.field_type),
                    .alignment = union_field.alignment,
                };
            }

            // TODO: https://github.com/ziglang/zig/issues/8114
            var decoder_union_ti = @typeInfo(T);
            decoder_union_ti.Union.fields = &decoder_union_fields;

            return @Type(decoder_union_ti);
        }

        pub fn toUnion(this: @This()) !decoder_union(T) {
            if (@typeInfo(T) != .Union) @compileError(@typeName(T) ++ " is not a union");

            const TagType = @typeInfo(T).Union.tag_type.?;
            const size = space_required(TagType);
            const child_ptr = this.ptr + size;

            //const tag_value = std.mem.readIntLittle(TagValueType, this.bytes[this.ptr..][0..size]);
            const tag = try (Decoder(TagType){ .bytes = this.bytes, .ptr = this.ptr }).tryToValue();

            inline for (@typeInfo(T).Union.fields) |union_field, idx| {
                if (tag == comptime std.meta.stringToEnum(TagType, union_field.name).?) {
                    return @unionInit(decoder_union(T), union_field.name, Decoder(union_field.field_type){
                        .bytes = this.bytes,
                        .ptr = child_ptr,
                    });
                }
            }

            return error.InvalidEnumValue;
        }

        pub fn access_type(comptime access_string: []const u8) type {
            const State = enum {
                uninit,
                element_idx,
                field_name,
            };
            var state = State.uninit;
            var current_type = @This();
            var field_name_start = 0;

            for (access_string) |c, idx| {
                switch (state) {
                    .uninit => switch (c) {
                        '[' => {
                            const info = @typeInfo(current_type.T);
                            const is_array = info == .Array;
                            const is_slice = info == .Pointer and info.Pointer.size == .Slice;
                            if (!(is_array or is_slice)) @compileError("Attempt to access non-array type " ++ @typeName(current_type.T) ++ " through indexing");
                            state = .element_idx;
                        },
                        '.' => {
                            const info = @typeInfo(current_type.T);
                            const is_struct = info == .Struct;
                            const is_enum = info == .Enum;
                            const is_union = info == .Union;
                            if (!(is_struct or is_enum or is_union)) @compileError("Attempt to access field in type " ++ @typeName(current_type.T));
                            field_name_start = idx + 1;
                            state = .field_name;
                        },
                        else => @compileError("Invalid character '" ++ [_]u8{c} ++ "'"),
                    },
                    .element_idx => switch (c) {
                        '0'...'9' => {},
                        ']' => {
                            const current_child_type = current_type.child_type();
                            current_type = Decoder(current_child_type);
                            state = .uninit;
                        },
                        else => @compileError("Invalid character '" ++ [_]u8{c} ++ "'"),
                    },
                    .field_name => {
                        const end_idx = switch (c) {
                            'a'...'z', 'A'...'Z', '0'...'9', '_' => if (idx + 1 >= access_string.len) idx + 1 else continue,
                            '[', '.' => idx,
                            else => @compileError("Invalid character '" ++ [_]u8{c} ++ "'"),
                        };

                        const field_name = access_string[field_name_start..end_idx];
                        comptime var child_field_type: ?type = null;
                        inline for (std.meta.fields(current_type.T)) |child_field| {
                            if (comptime std.mem.eql(u8, field_name, child_field.name)) {
                                child_field_type = child_field.field_type;
                                break;
                            }
                        }
                        if (child_field_type == null) {
                            @compileError("Unknown field '" ++ field_name ++ "' in type " ++ @typeName(current_type.T));
                        }
                        current_type = Decoder(child_field_type.?);

                        if (idx + 1 >= access_string.len) return current_type;

                        const info = @typeInfo(current_type.T);
                        if (c == '.') {
                            const is_struct = info == .Struct;
                            const is_enum = info == .Enum;
                            const is_union = info == .Union;
                            if (!(is_struct or is_enum or is_union)) @compileError("Attempt to access field in type " ++ @typeName(current_type.T));
                            field_name_start = idx + 1;
                            state = .field_name;
                        } else {
                            const is_array = info == .Array;
                            const is_slice = info == .Pointer and info.Pointer.size == .Slice;
                            if (!(is_array or is_slice)) @compileError("Attempt to access non-array type " ++ @typeName(current_type.T) ++ " through indexing");
                            state = .element_idx;
                        }
                    },
                }
            }

            return current_type;
        }

        pub fn access(this: @This(), comptime access_string: []const u8) access_type(access_string) {
            return this.tryAccess(access_string) catch unreachable;
        }

        pub fn tryAccess(this: @This(), comptime access_string: []const u8) !access_type(access_string) {
            const State = enum {
                uninit,
                element_idx,
                field_name,
            };
            comptime var state = State.uninit;
            comptime var element_idx_start = 0;
            comptime var field_name_start = 0;

            if (access_string.len == 0) return this;

            inline for (access_string) |c, idx| {
                switch (state) {
                    .uninit => switch (c) {
                        '[' => {
                            element_idx_start = idx + 1;
                            state = .element_idx;
                        },
                        '.' => {
                            field_name_start = idx + 1;
                            state = .field_name;
                        },
                        else => @compileError("Invalid character '" ++ [_]u8{c} ++ "' at index "),
                    },
                    .element_idx => switch (c) {
                        '0'...'9' => {},
                        ']' => {
                            const element_idx = try std.fmt.parseInt(u32, access_string[element_idx_start..idx], 10);
                            const accessed_element = try this.tryElement(element_idx);
                            return try accessed_element.tryAccess(access_string[idx + 1 ..]);
                        },
                        else => @compileError("Invalid character '" ++ [_]u8{c} ++ "'"),
                    },
                    .field_name => {
                        const end_idx = switch (c) {
                            'a'...'z', 'A'...'Z', '0'...'9', '_' => if (idx + 1 >= access_string.len) idx + 1 else continue,
                            '[', '.' => idx,
                            else => @compileError("Invalid character '" ++ [_]u8{c} ++ "'"),
                        };

                        const accessed_field = try this.tryField(access_string[field_name_start..end_idx]);
                        return try accessed_field.tryAccess(access_string[end_idx..]);
                    },
                }
            }

            return current_type;
        }
    };
}

test "convert data from memory to proto encoding" {
    const tags = [_][]const u8{
        "hello",
        "world",
    };
    // Slices are encoded with offsets of 32bits and lengths of 32bits
    const expected = [_]u8{
        // Tags slice
        0x08, 0x00, 0x00, 0x00, // pointer to tags array
        0x02, 0x00, 0x00, 0x00, // length of tags array (in # of elements)
        // Tags array
        // - slice for string 1
        0x18, 0x00, 0x00, 0x00, // pointer to string
        0x05, 0x00, 0x00, 0x00, // length of string
        // - slice for string 2
        0x1d, 0x00, 0x00, 0x00, // pointer to string
        0x05, 0x00, 0x00, 0x00, // length of string
        'h', 'e', 'l', 'l', 'o', // String 1
        'w', 'o', 'r', 'l', 'd', // String 2
    };

    const tags_proto = try encode(std.testing.allocator, @as([]const []const u8, &tags));
    defer std.testing.allocator.free(tags_proto);

    std.testing.expectEqualSlices(u8, &expected, tags_proto);
}

test "read data from proto encoding" {
    // Slices are encoded with offsets of 32bits and lengths of 32bits
    const bytes = [_]u8{
        // Tags slice
        0x08, 0x00, 0x00, 0x00, // pointer to tags array
        0x02, 0x00, 0x00, 0x00, // length of tags array (in # of elements)
        // Tags array
        // - slice for string 1
        0x18, 0x00, 0x00, 0x00, // pointer to string
        0x05, 0x00, 0x00, 0x00, // length of string
        // - slice for string 2
        0x1d, 0x00, 0x00, 0x00, // pointer to string
        0x05, 0x00, 0x00, 0x00, // length of string
        'h', 'e', 'l', 'l', 'o', // String 1
        'w', 'o', 'r', 'l', 'd', // String 2
    };

    const decoder = Decoder([]const []const u8).fromBytes(&bytes).?;

    std.testing.expectEqualSlices(u8, "hello", decoder.element(0).asSlice());
    std.testing.expectEqualSlices(u8, "world", decoder.element(1).asSlice());
}

test "write and read struct data from proto encoding" {
    const S = struct {
        start: u64,
        tags: []const []const u8,
    };

    const input_data = S{
        .start = 1337,
        .tags = &[_][]const u8{
            "coding",
            "augr",
            "hello world",
        },
    };

    // Slices are encoded with offsets of 32bits and lengths of 32bits
    const expected = [_]u8{
        // S struct
        0x39, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Start time
        0x10, 0x00, 0x00, 0x00, // pointer to tags array
        0x03, 0x00, 0x00, 0x00, // length of tags array (in # of elements)
        // Tags array
        // - slice for string 1
        0x28, 0x00, 0x00, 0x00, // pointer to string
        0x06, 0x00, 0x00, 0x00, // length of string
        // - slice for string 2
        0x2e, 0x00, 0x00, 0x00, // pointer to string
        0x04, 0x00, 0x00, 0x00, // length of string
        // - slice for string 3
        0x32, 0x00, 0x00, 0x00, // pointer to string
        0x0b, 0x00, 0x00, 0x00, // length of string
        'c', 'o', 'd', 'i', 'n', 'g', // String 1
        'a', 'u', 'g', 'r', // String 2
        'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', // String 3
    };

    // Test encoding struct
    const encoded_bytes = try encode(std.testing.allocator, input_data);
    defer std.testing.allocator.free(encoded_bytes);

    std.testing.expectEqualSlices(u8, &expected, encoded_bytes);

    // Test decoding struct
    const decoder = Decoder(S).fromBytes(encoded_bytes).?;

    std.testing.expectEqual(@as(u64, 1337), decoder.field("start").toValue());
    std.testing.expectEqualSlices(u8, input_data.tags[0], decoder.field("tags").element(0).asSlice());
    std.testing.expectEqualSlices(u8, input_data.tags[1], decoder.field("tags").element(1).asSlice());
    std.testing.expectEqualSlices(u8, input_data.tags[2], decoder.field("tags").element(2).asSlice());
}

fn testWriteThenDecode(allocator: *std.mem.Allocator, value: anytype) Decoder(@TypeOf(value)) {
    const encoded_bytes = encode(allocator, value) catch unreachable;
    return Decoder(@TypeOf(value)).fromBytes(encoded_bytes).?;
}

test "write and read optional" {
    {
        const decoder = testWriteThenDecode(std.testing.allocator, @as(?u64, null));
        defer std.testing.allocator.free(decoder.bytes);
        std.testing.expectEqual(@as(?u64, null), decoder.toValue());
    }
    {
        const decoder = testWriteThenDecode(std.testing.allocator, @as(?u64, 1337));
        defer std.testing.allocator.free(decoder.bytes);
        std.testing.expectEqual(@as(?u64, 1337), decoder.toValue());
    }
    {
        const decoder = testWriteThenDecode(std.testing.allocator, @as(?u8, 42));
        defer std.testing.allocator.free(decoder.bytes);
        std.testing.expectEqual(@as(?u8, 42), decoder.toValue());
    }
}

test "write and read array" {
    {
        const decoder = testWriteThenDecode(std.testing.allocator, @as([3]u8, "foo".*));
        defer std.testing.allocator.free(decoder.bytes);
        std.testing.expectEqual(@as([3]u8, "foo".*), decoder.toValue());
    }
    {
        const decoder = testWriteThenDecode(std.testing.allocator, @as([0]u8, .{}));
        defer std.testing.allocator.free(decoder.bytes);
        std.testing.expectEqual(@as([0]u8, .{}), decoder.toValue());
    }
}

test "write and read enum" {
    const E = enum(u8) {
        foo,
        bar,
    };
    {
        const decoder = testWriteThenDecode(std.testing.allocator, E.foo);
        defer std.testing.allocator.free(decoder.bytes);
        std.testing.expectEqual(E.foo, try decoder.tryToValue());
    }
    {
        const decoder = testWriteThenDecode(std.testing.allocator, E.bar);
        defer std.testing.allocator.free(decoder.bytes);
        std.testing.expectEqual(E.bar, try decoder.tryToValue());
    }
}

test "write and read union" {
    const E = enum(u8) {
        integer,
        text,
    };
    const U = union(E) {
        integer: u32,
        text: []const u8,
    };
    {
        const decoder = testWriteThenDecode(std.testing.allocator, U{ .integer = 42 });
        defer std.testing.allocator.free(decoder.bytes);
        switch (try decoder.toUnion()) {
            .integer => |int_decoder| {
                std.testing.expectEqual(@as(u32, 42), int_decoder.toValue());
            },
            else => unreachable,
        }
    }
    {
        const decoder = testWriteThenDecode(std.testing.allocator, U{ .text = "hello" });
        defer std.testing.allocator.free(decoder.bytes);
        switch (try decoder.toUnion()) {
            .text => |text_decoder| {
                std.testing.expectEqualSlices(u8, "hello", text_decoder.asSlice());
            },
            else => unreachable,
        }
    }
}

test "write and read graphs" {
    const N = struct {
        edges: []const *const @This(),
    };

    {
        // Empty graph
        const graph = N{ .edges = &.{} };
        const decoder = testWriteThenDecode(std.testing.allocator, graph);
        defer std.testing.allocator.free(decoder.bytes);
        std.testing.expectEqual(@as(u32, 0), decoder.field("edges").len());
    }
    {
        // Tree
        const n0 = N{ .edges = &.{} };
        const n1 = N{ .edges = &.{} };
        const n2 = N{ .edges = &.{ &n0, &n1 } };
        const n3 = N{ .edges = &.{} };
        const graph = N{ .edges = &.{ &n2, &n3 } };

        const decoder = testWriteThenDecode(std.testing.allocator, graph);
        defer std.testing.allocator.free(decoder.bytes);

        const root_edges = decoder.field("edges");
        std.testing.expectEqual(@as(u32, 2), root_edges.len());

        std.testing.expectEqual(@as(u32, 2), root_edges.element(0).deref().field("edges").len());
        std.testing.expectEqual(@as(u32, 0), root_edges.element(1).deref().field("edges").len());

        const elem0_edges = root_edges.element(0).deref().field("edges");
        std.testing.expectEqual(@as(u32, 0), elem0_edges.element(0).deref().field("edges").len());
        std.testing.expectEqual(@as(u32, 0), elem0_edges.element(1).deref().field("edges").len());
    }
    {
        const LN = struct { next: *const @This() };

        // cyclical graph
        var graph: LN = undefined;
        const n0 = LN{ .next = &graph };
        const n1 = LN{ .next = &n0 };
        graph = LN{ .next = &n1 };

        const decoder = testWriteThenDecode(std.testing.allocator, @as(*const LN, &graph));
        defer std.testing.allocator.free(decoder.bytes);

        const decoder_val = decoder.deref();
        var current: Decoder(LN) = decoder_val.field("next").deref();
        var iterations: u32 = 0;
        while (!std.meta.eql(decoder_val, current)) : (iterations += 1) {
            if (iterations > 100) std.debug.assert(false);

            const next = current.field("next").deref();
            current = next;
        }
    }
}

test "access function for accessing deeply nested data" {
    const FlightSegmentInfo = struct {
        flightNumber: []const u8,
        departureAirport: []const u8,
        arrivalAirport: []const u8,
    };
    const SeatInfo = struct {
        seatNumber: []const u8,
        available: bool,
    };
    const CabinType = enum(u8) {
        First,
        Economy,
    };
    const RowInfo = struct {
        cabinType: CabinType,
        seats: []const SeatInfo,
    };
    const SeatMapReponse = struct {
        flightSegmentInfo: FlightSegmentInfo,
        seatMap: []const RowInfo,
    };
    const AirSeatMap = struct {
        responses: []const SeatMapReponse,
    };

    const air_seat_map = AirSeatMap{
        .responses = &[_]SeatMapReponse{.{
            .flightSegmentInfo = .{
                .flightNumber = "1179",
                .departureAirport = "LAS",
                .arrivalAirport = "IAH",
            },
            .seatMap = &[_]RowInfo{
                .{
                    .cabinType = .First,
                    .seats = &.{
                        .{ .seatNumber = "1A", .available = false },
                        .{ .seatNumber = "1B", .available = false },
                        .{ .seatNumber = "1E", .available = false },
                        .{ .seatNumber = "1F", .available = false },
                    },
                },
                .{
                    .cabinType = .Economy,
                    .seats = &.{
                        .{ .seatNumber = "7A", .available = false },
                        .{ .seatNumber = "7B", .available = false },
                        .{ .seatNumber = "7C", .available = true },
                        .{ .seatNumber = "7D", .available = false },
                        .{ .seatNumber = "7E", .available = false },
                        .{ .seatNumber = "7F", .available = false },
                    },
                },
            },
        }},
    };

    @setEvalBranchQuota(10000);
    const decoder = testWriteThenDecode(std.testing.allocator, air_seat_map);
    defer std.testing.allocator.free(decoder.bytes);

    std.testing.expectEqualSlices(u8, "1179", decoder.access(".responses[0].flightSegmentInfo.flightNumber").asSlice());
    std.testing.expectEqualSlices(u8, "LAS", decoder.access(".responses[0].flightSegmentInfo.departureAirport").asSlice());
    std.testing.expectEqualSlices(u8, "IAH", decoder.access(".responses[0].flightSegmentInfo.arrivalAirport").asSlice());

    std.testing.expectEqual(CabinType.First, try decoder.access(".responses[0].seatMap[0].cabinType").tryToValue());
    std.testing.expectEqualSlices(u8, "1A", decoder.access(".responses[0].seatMap[0].seats[0].seatNumber").asSlice());
    std.testing.expectEqual(false, try decoder.access(".responses[0].seatMap[0].seats[0].available").tryToValue());

    std.testing.expectEqual(CabinType.Economy, try decoder.access(".responses[0].seatMap[1].cabinType").tryToValue());
    std.testing.expectEqualSlices(u8, "7C", decoder.access(".responses[0].seatMap[1].seats[2].seatNumber").asSlice());
    std.testing.expectEqual(true, try decoder.access(".responses[0].seatMap[1].seats[2].available").tryToValue());
}
