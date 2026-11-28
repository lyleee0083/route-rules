# route-rules Project Requirements

## Product and architecture

- Generate sing-box TUN configurations, shared routing rules, and binary SRS for Windows, Linux, macOS, Android, and iOS on `main`. The maintained [xiaomi-be7000 variant](https://github.com/lyleee0083/route-rules/tree/xiaomi-be7000) owns BE7000 OpenWrt package assembly and its branch build inputs.
- Use [config/sing-box-core-base.json](config/sing-box-core-base.json) as the common client configuration, [config/client-profiles.json](config/client-profiles.json) for operating-system differences, and [routing/routing-sources.json](routing/routing-sources.json) for input formats, sources, and priority.
- Preserve rule precedence by format and category. Client traffic applies IPv6 rejection, IPv4 or port rejection, then effective direct rules, followed by proxy fallback. Keep DNS grouping and rejection rules distinct from traffic routing. Document imported sources, revisions, and licenses.
- Keep real node addresses and credentials in local configuration. Deliver generated configurations with example node values and compatible SRS files.

## Build and acceptance

- Use the [Clients workflow](.github/workflows/clients.yml) to refresh inputs, run routing and archive tests, generate and verify client profiles, and decode-check SRS with the pinned checker. Use the variant's `be7000.yml` for its OpenWrt artifacts.
- Use [VERSION](VERSION) and the workflow to version the main client archive `route-rules-<version>.zip`. Preserve its relative `rule-set` layout and keep input provenance in the build evidence.
- Report actual client TUN, node connectivity, and OpenWrt device acceptance separately from CI rule and package verification.
