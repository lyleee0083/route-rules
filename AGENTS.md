# Xiaomi BE7000 branch instructions

Apply the [shared repository instructions on main](https://github.com/lyleee0083/route-rules/blob/main/AGENTS.md) together with these branch rules.

- Keep OpenWrt source, tests, and documentation in `openwrt/`. Maintain shared client source and routing policy on `main`.
- Build with the BE7000 GitHub Actions workflow on `ubuntu-latest`. Pin and record the main commit used to assemble the OpenWrt build.
- Keep the two runtime cores external to the configuration ZIP. Treat configuration generation, packaging, and router deployment as separate scopes. Follow the [integration ownership document](openwrt/docs/USER-SETTING-OWNERSHIP.md).
