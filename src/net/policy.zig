const std = @import("std");

/// Network operation modes
pub const NetworkMode = enum {
    /// No network access allowed
    locked_down,
    /// Only allowed domains/IPs can be accessed
    allowlist,
    /// Full network access (requires double opt-in)
    open,

    pub fn fromString(s: []const u8) ?NetworkMode {
        if (std.mem.eql(u8, s, "locked_down")) return .locked_down;
        if (std.mem.eql(u8, s, "allowlist")) return .allowlist;
        if (std.mem.eql(u8, s, "open")) return .open;
        return null;
    }

    pub fn toString(self: NetworkMode) []const u8 {
        return switch (self) {
            .locked_down => "locked_down",
            .allowlist => "allowlist",
            .open => "open",
        };
    }
};

/// Protocol types for filtering
pub const Protocol = enum {
    tcp,
    udp,
    any,

    pub fn fromString(s: []const u8) ?Protocol {
        if (std.mem.eql(u8, s, "tcp")) return .tcp;
        if (std.mem.eql(u8, s, "udp")) return .udp;
        if (std.mem.eql(u8, s, "any")) return .any;
        return null;
    }
};

/// A domain-based access rule
pub const DomainRule = struct {
    /// Domain pattern (supports wildcards like *.example.com)
    pattern: []const u8,
    /// Allowed port range (null = all ports)
    port_min: ?u16 = null,
    port_max: ?u16 = null,
    /// Protocol filter
    protocol: Protocol = .any,
    /// Whether this is an allow or deny rule
    allow: bool = true,

    /// Checks if a domain matches this rule
    pub fn matches(self: *const DomainRule, domain: []const u8) bool {
        return matchDomainPattern(self.pattern, domain);
    }

    /// Checks if a port is within the allowed range
    pub fn portAllowed(self: *const DomainRule, port: u16) bool {
        if (self.port_min == null and self.port_max == null) return true;
        const min = self.port_min orelse 0;
        const max = self.port_max orelse 65535;
        return port >= min and port <= max;
    }
};

/// An IP-based access rule (CIDR notation)
pub const IpRule = struct {
    /// IP address (IPv4 as 4 bytes)
    address: [4]u8,
    /// CIDR prefix length (0-32)
    prefix_len: u8,
    /// Allowed port range
    port_min: ?u16 = null,
    port_max: ?u16 = null,
    /// Protocol filter
    protocol: Protocol = .any,
    /// Whether this is an allow or deny rule
    allow: bool = true,

    /// Checks if an IP address matches this rule
    pub fn matches(self: *const IpRule, ip: [4]u8) bool {
        const mask = self.getMask();
        return maskedEqual(self.address, ip, mask);
    }

    /// Gets the subnet mask from prefix length
    pub fn getMask(self: *const IpRule) [4]u8 {
        if (self.prefix_len == 0) return [4]u8{ 0, 0, 0, 0 };
        if (self.prefix_len >= 32) return [4]u8{ 255, 255, 255, 255 };

        var mask: u32 = 0;
        var i: u5 = 0;
        while (i < self.prefix_len) : (i += 1) {
            mask |= (@as(u32, 1) << (31 - i));
        }

        return [4]u8{
            @intCast((mask >> 24) & 0xFF),
            @intCast((mask >> 16) & 0xFF),
            @intCast((mask >> 8) & 0xFF),
            @intCast(mask & 0xFF),
        };
    }

    /// Checks if a port is within the allowed range
    pub fn portAllowed(self: *const IpRule, port: u16) bool {
        if (self.port_min == null and self.port_max == null) return true;
        const min = self.port_min orelse 0;
        const max = self.port_max orelse 65535;
        return port >= min and port <= max;
    }
};

/// A resolved IP from DNS lookup (with TTL)
pub const ResolvedIp = struct {
    /// The IP address
    address: [4]u8,
    /// Original domain that resolved to this IP
    domain: []const u8,
    /// Timestamp when this entry expires
    expires_at: i64,
};

/// Main network policy configuration
pub const NetworkPolicy = struct {
    allocator: std.mem.Allocator,
    /// Current network mode
    mode: NetworkMode = .locked_down,
    /// DNS-based domain rules
    allowed_domains: std.ArrayList(DomainRule),
    /// Direct IP/CIDR rules
    allowed_ips: std.ArrayList(IpRule),
    /// Custom DNS servers to use
    dns_servers: std.ArrayList([4]u8),
    /// Resolved IPs from DNS lookups (cache)
    resolved_ips: std.ArrayList(ResolvedIp),
    /// Whether to inspect TLS SNI for domain verification
    inspect_tls_sni: bool = false,
    /// Maximum TTL for DNS cache entries (caps server-provided TTL)
    max_dns_ttl_seconds: u32 = 300,

    pub fn init(allocator: std.mem.Allocator) NetworkPolicy {
        return .{
            .allocator = allocator,
            .allowed_domains = .empty,
            .allowed_ips = .empty,
            .dns_servers = .empty,
            .resolved_ips = .empty,
        };
    }

    pub fn deinit(self: *NetworkPolicy) void {
        // Free domain pattern strings
        for (self.allowed_domains.items) |rule| {
            self.allocator.free(rule.pattern);
        }
        self.allowed_domains.deinit(self.allocator);

        // Free resolved IP domain strings
        for (self.resolved_ips.items) |resolved| {
            self.allocator.free(resolved.domain);
        }
        self.resolved_ips.deinit(self.allocator);

        self.allowed_ips.deinit(self.allocator);
        self.dns_servers.deinit(self.allocator);
    }

    /// Adds a domain rule to the allowlist
    pub fn addDomainRule(self: *NetworkPolicy, pattern: []const u8) !void {
        const owned_pattern = try self.allocator.dupe(u8, pattern);
        try self.allowed_domains.append(self.allocator, .{ .pattern = owned_pattern });
    }

    /// Adds a domain rule with port restrictions
    pub fn addDomainRuleWithPorts(
        self: *NetworkPolicy,
        pattern: []const u8,
        port_min: ?u16,
        port_max: ?u16,
    ) !void {
        const owned_pattern = try self.allocator.dupe(u8, pattern);
        try self.allowed_domains.append(self.allocator, .{
            .pattern = owned_pattern,
            .port_min = port_min,
            .port_max = port_max,
        });
    }

    /// Adds an IP rule to the allowlist
    pub fn addIpRule(self: *NetworkPolicy, address: [4]u8, prefix_len: u8) !void {
        try self.allowed_ips.append(self.allocator, .{
            .address = address,
            .prefix_len = prefix_len,
        });
    }

    /// Adds a DNS server
    pub fn addDnsServer(self: *NetworkPolicy, ip: [4]u8) !void {
        try self.dns_servers.append(self.allocator, ip);
    }

    /// Checks if a domain is allowed by the policy
    pub fn isDomainAllowed(self: *const NetworkPolicy, domain: []const u8) bool {
        return self.isDomainAllowedOnPort(domain, null);
    }

    /// Checks if a domain is allowed on a specific port
    pub fn isDomainAllowedOnPort(self: *const NetworkPolicy, domain: []const u8, port: ?u16) bool {
        switch (self.mode) {
            .locked_down => return false,
            .open => return true,
            .allowlist => {
                for (self.allowed_domains.items) |rule| {
                    if (rule.matches(domain)) {
                        if (port) |p| {
                            if (rule.portAllowed(p)) return rule.allow;
                        } else {
                            return rule.allow;
                        }
                    }
                }
                return false;
            },
        }
    }

    /// Checks if an IP is allowed by the policy
    pub fn isIpAllowed(self: *const NetworkPolicy, ip: [4]u8) bool {
        return self.isIpAllowedOnPort(ip, null);
    }

    /// Checks if an IP is allowed on a specific port
    pub fn isIpAllowedOnPort(self: *const NetworkPolicy, ip: [4]u8, port: ?u16) bool {
        switch (self.mode) {
            .locked_down => return false,
            .open => return true,
            .allowlist => {
                // Check direct IP rules first
                for (self.allowed_ips.items) |rule| {
                    if (rule.matches(ip)) {
                        if (port) |p| {
                            if (rule.portAllowed(p)) return rule.allow;
                        } else {
                            return rule.allow;
                        }
                    }
                }

                // Check resolved IPs from DNS
                const now = std.time.timestamp();
                for (self.resolved_ips.items) |resolved| {
                    if (resolved.expires_at > now and std.mem.eql(u8, &resolved.address, &ip)) {
                        return true;
                    }
                }

                return false;
            },
        }
    }

    /// Adds a resolved IP to the cache
    pub fn addResolvedIp(self: *NetworkPolicy, domain: []const u8, ip: [4]u8, ttl: u32) !void {
        const capped_ttl = @min(ttl, self.max_dns_ttl_seconds);
        const expires_at = std.time.timestamp() + @as(i64, capped_ttl);

        const owned_domain = try self.allocator.dupe(u8, domain);
        try self.resolved_ips.append(self.allocator, .{
            .address = ip,
            .domain = owned_domain,
            .expires_at = expires_at,
        });
    }

    /// Cleans up expired entries from the resolved IP cache
    pub fn cleanupExpiredEntries(self: *NetworkPolicy) void {
        const now = std.time.timestamp();
        var i: usize = 0;
        while (i < self.resolved_ips.items.len) {
            if (self.resolved_ips.items[i].expires_at <= now) {
                self.allocator.free(self.resolved_ips.items[i].domain);
                _ = self.resolved_ips.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Validates that open mode is allowed (requires env var)
    pub fn validateOpenMode(self: *const NetworkPolicy) bool {
        if (self.mode != .open) return true;

        // Open mode requires M80_ALLOW_OPEN_NETWORK environment variable
        const env_var = std.process.getEnvVarOwned(self.allocator, "M80_ALLOW_OPEN_NETWORK") catch {
            return false;
        };
        defer self.allocator.free(env_var);

        return std.mem.eql(u8, env_var, "1") or std.mem.eql(u8, env_var, "true");
    }
};

/// Matches a domain against a pattern (supports wildcards)
/// *.example.com matches sub.example.com but NOT example.com
pub fn matchDomainPattern(pattern: []const u8, domain: []const u8) bool {
    // Exact match
    if (std.mem.eql(u8, pattern, domain)) return true;

    // Wildcard match
    if (std.mem.startsWith(u8, pattern, "*.")) {
        const suffix = pattern[1..]; // .example.com
        if (std.mem.endsWith(u8, domain, suffix)) {
            // Make sure there's something before the suffix
            const prefix_len = domain.len - suffix.len;
            if (prefix_len > 0) {
                // Make sure the prefix doesn't contain a dot (for *.example.com, foo.bar.example.com should NOT match)
                // Actually, per the spec *.example.com SHOULD match sub.example.com but not example.com
                // Let's allow multi-level subdomains
                return true;
            }
        }
    }

    return false;
}

/// Compares two IPs with a mask
fn maskedEqual(a: [4]u8, b: [4]u8, mask: [4]u8) bool {
    return (a[0] & mask[0]) == (b[0] & mask[0]) and
        (a[1] & mask[1]) == (b[1] & mask[1]) and
        (a[2] & mask[2]) == (b[2] & mask[2]) and
        (a[3] & mask[3]) == (b[3] & mask[3]);
}

/// Parses an IP address string into bytes
pub fn parseIpAddress(ip_str: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, ip_str, '.');
    var i: usize = 0;

    while (parts.next()) |part| {
        if (i >= 4) return null;
        result[i] = std.fmt.parseInt(u8, part, 10) catch return null;
        i += 1;
    }

    if (i != 4) return null;
    return result;
}

/// Parses a CIDR notation string (e.g., "10.0.0.0/8")
pub fn parseCidr(cidr_str: []const u8) ?IpRule {
    const slash_idx = std.mem.indexOfScalar(u8, cidr_str, '/') orelse {
        // No prefix, assume /32
        const ip = parseIpAddress(cidr_str) orelse return null;
        return IpRule{ .address = ip, .prefix_len = 32 };
    };

    const ip_str = cidr_str[0..slash_idx];
    const prefix_str = cidr_str[slash_idx + 1 ..];

    const ip = parseIpAddress(ip_str) orelse return null;
    const prefix_len = std.fmt.parseInt(u8, prefix_str, 10) catch return null;

    if (prefix_len > 32) return null;

    return IpRule{ .address = ip, .prefix_len = prefix_len };
}

// Tests
test "policy: NetworkMode fromString/toString" {
    try std.testing.expectEqual(NetworkMode.locked_down, NetworkMode.fromString("locked_down").?);
    try std.testing.expectEqual(NetworkMode.allowlist, NetworkMode.fromString("allowlist").?);
    try std.testing.expectEqual(NetworkMode.open, NetworkMode.fromString("open").?);
    try std.testing.expect(NetworkMode.fromString("invalid") == null);

    try std.testing.expectEqualStrings("locked_down", NetworkMode.locked_down.toString());
    try std.testing.expectEqualStrings("allowlist", NetworkMode.allowlist.toString());
}

test "policy: matchDomainPattern exact match" {
    try std.testing.expect(matchDomainPattern("example.com", "example.com"));
    try std.testing.expect(!matchDomainPattern("example.com", "other.com"));
}

test "policy: matchDomainPattern wildcard" {
    try std.testing.expect(matchDomainPattern("*.example.com", "sub.example.com"));
    try std.testing.expect(matchDomainPattern("*.example.com", "deep.sub.example.com"));
    try std.testing.expect(!matchDomainPattern("*.example.com", "example.com"));
    try std.testing.expect(!matchDomainPattern("*.example.com", "other.com"));
}

test "policy: IpRule mask calculation" {
    const rule8 = IpRule{ .address = [4]u8{ 10, 0, 0, 0 }, .prefix_len = 8 };
    try std.testing.expectEqual([4]u8{ 255, 0, 0, 0 }, rule8.getMask());

    const rule16 = IpRule{ .address = [4]u8{ 172, 16, 0, 0 }, .prefix_len = 16 };
    try std.testing.expectEqual([4]u8{ 255, 255, 0, 0 }, rule16.getMask());

    const rule24 = IpRule{ .address = [4]u8{ 192, 168, 1, 0 }, .prefix_len = 24 };
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 0 }, rule24.getMask());

    const rule32 = IpRule{ .address = [4]u8{ 1, 2, 3, 4 }, .prefix_len = 32 };
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 255 }, rule32.getMask());
}

test "policy: IpRule matches" {
    const rule = IpRule{ .address = [4]u8{ 10, 0, 0, 0 }, .prefix_len = 8 };
    try std.testing.expect(rule.matches([4]u8{ 10, 1, 2, 3 }));
    try std.testing.expect(rule.matches([4]u8{ 10, 255, 255, 255 }));
    try std.testing.expect(!rule.matches([4]u8{ 11, 0, 0, 1 }));
}

test "policy: parseIpAddress" {
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, parseIpAddress("192.168.1.1").?);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, parseIpAddress("10.0.0.1").?);
    try std.testing.expect(parseIpAddress("invalid") == null);
    try std.testing.expect(parseIpAddress("256.0.0.1") == null);
}

test "policy: parseCidr" {
    const rule = parseCidr("10.0.0.0/8").?;
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 0 }, rule.address);
    try std.testing.expectEqual(@as(u8, 8), rule.prefix_len);

    const single = parseCidr("192.168.1.1").?;
    try std.testing.expectEqual(@as(u8, 32), single.prefix_len);

    try std.testing.expect(parseCidr("invalid") == null);
    try std.testing.expect(parseCidr("10.0.0.0/33") == null);
}

test "policy: NetworkPolicy basic operations" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();

    // Default is locked down
    try std.testing.expect(!policy.isDomainAllowed("example.com"));

    // Switch to allowlist and add a domain
    policy.mode = .allowlist;
    try policy.addDomainRule("api.anthropic.com");

    try std.testing.expect(policy.isDomainAllowed("api.anthropic.com"));
    try std.testing.expect(!policy.isDomainAllowed("other.com"));
}

test "policy: NetworkPolicy IP rules" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();

    policy.mode = .allowlist;
    try policy.addIpRule([4]u8{ 10, 0, 0, 0 }, 8);

    try std.testing.expect(policy.isIpAllowed([4]u8{ 10, 1, 2, 3 }));
    try std.testing.expect(!policy.isIpAllowed([4]u8{ 192, 168, 1, 1 }));
}

test "policy: DomainRule port filtering" {
    const rule = DomainRule{
        .pattern = "example.com",
        .port_min = 443,
        .port_max = 443,
    };

    try std.testing.expect(rule.portAllowed(443));
    try std.testing.expect(!rule.portAllowed(80));
    try std.testing.expect(!rule.portAllowed(8080));
}
