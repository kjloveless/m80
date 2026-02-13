//! Network Policy Engine
//!
//! This module implements network access control for VMs. It defines rules
//! for which domains and IP addresses the guest can connect to, providing
//! defense-in-depth even if the hypervisor is compromised.
//!
//! ## Network Modes
//! - `locked_down`: No network access allowed (default, most secure)
//! - `allowlist`: Only explicitly allowed domains/IPs can be accessed
//! - `open`: Full network access (requires M80_ALLOW_OPEN_NETWORK env var)
//!
//! ## Domain Rules
//! Domain rules support wildcards: `*.example.com` matches `sub.example.com`
//! but not `example.com` itself. Rules can also specify port ranges.
//!
//! ## IP Rules (CIDR)
//! IP rules use CIDR notation: `10.0.0.0/8` matches the entire 10.x.x.x range.
//! A plain IP like `192.168.1.1` is treated as `/32` (single host).
//!
//! ## DNS Resolution Cache
//! When a domain is resolved via DNS, the resulting IP is cached with TTL.
//! This allows the allowlist to work even after DNS resolution, since the
//! guest may connect directly to the IP after lookup.

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
    /// Maximum number of entries in DNS resolution cache (prevents memory exhaustion)
    max_dns_cache_entries: usize = 1024,

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
                // First matching rule wins.
                for (self.allowed_domains.items) |rule| {
                    if (rule.matches(domain)) {
                        const port_ok = if (port) |p| rule.portAllowed(p) else true;
                        if (port_ok) {
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
                        const port_ok = if (port) |p| rule.portAllowed(p) else true;
                        if (port_ok) {
                            return rule.allow;
                        }
                    }
                }

                // Check resolved IPs from DNS (cache only applies in allowlist mode)
                @constCast(self).cleanupExpiredEntries();
                for (self.resolved_ips.items) |resolved| {
                    if (!std.mem.eql(u8, &resolved.address, &ip)) continue;
                    if (port) |p| {
                        if (self.isDomainAllowedOnPort(resolved.domain, p)) return true;
                    } else if (self.isDomainAllowed(resolved.domain)) {
                        return true;
                    }
                }

                return false;
            },
        }
    }

    /// Adds a resolved IP to the cache.
    /// Deduplicates entries with same domain+IP, evicts expired entries,
    /// and enforces max_dns_cache_entries limit.
    pub fn addResolvedIp(self: *NetworkPolicy, domain: []const u8, ip: [4]u8, ttl: u32) !void {
        const capped_ttl = @min(ttl, self.max_dns_ttl_seconds);
        const now = std.time.timestamp();
        const expires_at = now + @as(i64, capped_ttl);

        // Check for existing entry with same domain+IP and update expiry
        for (self.resolved_ips.items) |*entry| {
            if (std.mem.eql(u8, entry.domain, domain) and std.mem.eql(u8, &entry.address, &ip)) {
                entry.expires_at = expires_at;
                return;
            }
        }

        // Evict expired entries before adding
        self.cleanupExpiredEntries();

        // If still at limit, evict the entry with earliest expiry
        if (self.resolved_ips.items.len >= self.max_dns_cache_entries) {
            var oldest_idx: usize = 0;
            var oldest_expires: i64 = std.math.maxInt(i64);
            for (self.resolved_ips.items, 0..) |entry, i| {
                if (entry.expires_at < oldest_expires) {
                    oldest_expires = entry.expires_at;
                    oldest_idx = i;
                }
            }
            self.allocator.free(self.resolved_ips.items[oldest_idx].domain);
            _ = self.resolved_ips.swapRemove(oldest_idx);
        }

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
                // Allow multi-level subdomains (e.g., deep.sub.example.com).
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

pub const DomainSpec = struct {
    domain: []const u8,
    port_min: ?u16 = null,
    port_max: ?u16 = null,
};

fn isValidDomainLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > 63) return false;
    if (label[0] == '-' or label[label.len - 1] == '-') return false;
    for (label) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '-') return false;
    }
    return true;
}

pub fn isValidDomainPattern(pattern: []const u8) bool {
    const trimmed = std.mem.trim(u8, pattern, " \t\r\n");
    if (trimmed.len == 0) return false;

    const wildcard = std.mem.startsWith(u8, trimmed, "*.");
    const domain = if (wildcard) trimmed[2..] else trimmed;
    if (domain.len == 0) return false;
    if (std.mem.indexOfScalar(u8, domain, '*') != null) return false;
    if (!wildcard and std.mem.indexOfScalar(u8, trimmed, '*') != null) return false;
    if (domain[0] == '.' or domain[domain.len - 1] == '.') return false;

    var labels = std.mem.splitScalar(u8, domain, '.');
    while (labels.next()) |label| {
        if (!isValidDomainLabel(label)) return false;
    }
    return true;
}

pub fn parseDomainSpec(spec: []const u8) ?DomainSpec {
    const trimmed = std.mem.trim(u8, spec, " \t\r\n");
    if (trimmed.len == 0) return null;

    var colon_count: usize = 0;
    for (trimmed) |ch| {
        if (ch == ':') colon_count += 1;
    }
    if (colon_count > 1) return null;

    if (colon_count == 1) {
        const idx = std.mem.lastIndexOfScalar(u8, trimmed, ':') orelse return null;
        const domain = std.mem.trim(u8, trimmed[0..idx], " \t\r\n");
        const port_raw = std.mem.trim(u8, trimmed[idx + 1 ..], " \t\r\n");
        if (!isValidDomainPattern(domain)) return null;
        const port = std.fmt.parseInt(u16, port_raw, 10) catch return null;
        if (port == 0) return null;
        return .{
            .domain = domain,
            .port_min = port,
            .port_max = port,
        };
    }

    if (!isValidDomainPattern(trimmed)) return null;
    return .{
        .domain = trimmed,
    };
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

// =============================================================================
// TESTS
// =============================================================================

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

test "policy: matchDomainPattern wildcard edge cases" {
    try std.testing.expect(matchDomainPattern("*.example.com", "a.example.com"));
    try std.testing.expect(!matchDomainPattern("*.example.com", "example.com.evil"));
    try std.testing.expect(!matchDomainPattern("*.example.com", "badexample.com"));
    try std.testing.expect(!matchDomainPattern("*.example.com", "example.com"));
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

test "policy: parseDomainSpec supports plain and domain-port entries" {
    const plain = parseDomainSpec("example.com").?;
    try std.testing.expectEqualStrings("example.com", plain.domain);
    try std.testing.expect(plain.port_min == null);

    const wildcard = parseDomainSpec("*.example.com").?;
    try std.testing.expectEqualStrings("*.example.com", wildcard.domain);
    try std.testing.expect(wildcard.port_min == null);

    const with_port = parseDomainSpec("example.com:443").?;
    try std.testing.expectEqualStrings("example.com", with_port.domain);
    try std.testing.expectEqual(@as(?u16, 443), with_port.port_min);
    try std.testing.expectEqual(@as(?u16, 443), with_port.port_max);
}

test "policy: parseDomainSpec rejects malformed values" {
    try std.testing.expect(parseDomainSpec("") == null);
    try std.testing.expect(parseDomainSpec("example.com:") == null);
    try std.testing.expect(parseDomainSpec("example.com:abc") == null);
    try std.testing.expect(parseDomainSpec("example.com:0") == null);
    try std.testing.expect(parseDomainSpec(".example.com") == null);
    try std.testing.expect(parseDomainSpec("example..com") == null);
    try std.testing.expect(parseDomainSpec("bad*pattern.com") == null);
    try std.testing.expect(parseDomainSpec("example.com:443:10") == null);
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

test "policy: NetworkPolicy domain allowlist with ports" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();

    policy.mode = .allowlist;
    try policy.addDomainRuleWithPorts("example.com", 443, 443);

    try std.testing.expect(policy.isDomainAllowedOnPort("example.com", 443));
    try std.testing.expect(!policy.isDomainAllowedOnPort("example.com", 80));
}

test "policy: NetworkPolicy domain deny rule" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();

    policy.mode = .allowlist;
    try policy.allowed_domains.append(allocator, .{
        .pattern = try allocator.dupe(u8, "blocked.example.com"),
        .allow = false,
    });

    try std.testing.expect(!policy.isDomainAllowed("blocked.example.com"));
}

test "policy: NetworkPolicy IP allowlist with ports" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();

    policy.mode = .allowlist;
    try policy.allowed_ips.append(allocator, .{
        .address = [4]u8{ 10, 0, 0, 0 },
        .prefix_len = 8,
        .port_min = 22,
        .port_max = 22,
    });

    try std.testing.expect(policy.isIpAllowedOnPort([4]u8{ 10, 1, 2, 3 }, 22));
    try std.testing.expect(!policy.isIpAllowedOnPort([4]u8{ 10, 1, 2, 3 }, 80));
}

test "policy: NetworkPolicy resolved IP cache and cleanup" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();

    policy.mode = .allowlist;
    try policy.addDomainRule("example.com");
    try policy.addResolvedIp("example.com", [4]u8{ 1, 2, 3, 4 }, 60);

    try std.testing.expect(policy.isIpAllowed([4]u8{ 1, 2, 3, 4 }));

    const now = std.time.timestamp();
    policy.resolved_ips.items[0].expires_at = now - 1;
    policy.cleanupExpiredEntries();
    try std.testing.expect(!policy.isIpAllowed([4]u8{ 1, 2, 3, 4 }));
}

test "policy: resolved IP allowlist respects port rules" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();
    policy.mode = .allowlist;
    try policy.addDomainRuleWithPorts("example.com", 443, 443);
    try policy.addResolvedIp("example.com", [4]u8{ 1, 2, 3, 4 }, 60);

    try std.testing.expect(!policy.isIpAllowedOnPort([4]u8{ 1, 2, 3, 4 }, 80));
    try std.testing.expect(policy.isIpAllowedOnPort([4]u8{ 1, 2, 3, 4 }, 443));
}

test "policy: validateOpenMode requires env var" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();

    policy.mode = .open;
    try std.testing.expect(!policy.validateOpenMode());
}

test "policy: addResolvedIp caps ttl" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();

    policy.max_dns_ttl_seconds = 1;
    try policy.addResolvedIp("example.com", [4]u8{ 1, 2, 3, 4 }, 100);
    try std.testing.expect(policy.resolved_ips.items.len == 1);

    const now = std.time.timestamp();
    const ttl = policy.resolved_ips.items[0].expires_at - now;
    try std.testing.expect(ttl <= 1);
}

test "policy: cleanupExpiredEntries removes expired" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();

    try policy.addResolvedIp("example.com", [4]u8{ 1, 2, 3, 4 }, 60);
    try std.testing.expectEqual(@as(usize, 1), policy.resolved_ips.items.len);

    policy.resolved_ips.items[0].expires_at = std.time.timestamp() - 1;
    policy.cleanupExpiredEntries();
    try std.testing.expectEqual(@as(usize, 0), policy.resolved_ips.items.len);
}

test "policy: allowlist uses first matching rule" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();
    policy.mode = .allowlist;

    try policy.allowed_domains.append(allocator, .{
        .pattern = try allocator.dupe(u8, "example.com"),
        .allow = false,
    });
    try policy.allowed_domains.append(allocator, .{
        .pattern = try allocator.dupe(u8, "example.com"),
        .allow = true,
    });

    try std.testing.expect(!policy.isDomainAllowed("example.com"));
}

test "policy: open mode allows domain and ip" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();
    policy.mode = .open;

    try std.testing.expect(policy.isDomainAllowed("example.com"));
    try std.testing.expect(policy.isIpAllowed([4]u8{ 1, 2, 3, 4 }));
}

test "policy: locked_down denies domain and ip" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();
    policy.mode = .locked_down;

    try std.testing.expect(!policy.isDomainAllowed("example.com"));
    try std.testing.expect(!policy.isIpAllowed([4]u8{ 1, 2, 3, 4 }));
}

test "policy: addResolvedIp deduplicates same domain and ip" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();

    try policy.addResolvedIp("example.com", [4]u8{ 1, 2, 3, 4 }, 60);
    try policy.addResolvedIp("example.com", [4]u8{ 1, 2, 3, 4 }, 120);

    // Should still be only 1 entry, not 2
    try std.testing.expectEqual(@as(usize, 1), policy.resolved_ips.items.len);
}

test "policy: addResolvedIp enforces cache limit" {
    const allocator = std.testing.allocator;

    var policy = NetworkPolicy.init(allocator);
    defer policy.deinit();
    policy.max_dns_cache_entries = 3;

    try policy.addResolvedIp("a.com", [4]u8{ 1, 0, 0, 1 }, 60);
    try policy.addResolvedIp("b.com", [4]u8{ 2, 0, 0, 2 }, 60);
    try policy.addResolvedIp("c.com", [4]u8{ 3, 0, 0, 3 }, 60);

    try std.testing.expectEqual(@as(usize, 3), policy.resolved_ips.items.len);

    // Adding a 4th should evict one
    try policy.addResolvedIp("d.com", [4]u8{ 4, 0, 0, 4 }, 60);
    try std.testing.expectEqual(@as(usize, 3), policy.resolved_ips.items.len);
}
