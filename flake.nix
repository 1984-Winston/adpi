{
  description = "DPI-bypassing transparent proxy";

  outputs =
    { ... }:
    {
      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          package = pkgs.rustPlatform.buildRustPackage {
            name = "adpi";

            src = lib.cleanSource ./.;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = [ pkgs.rustPlatform.bindgenHook ];
          };

          cfg = config.services.adpi;
        in
        {
          options = {
            services.adpi = {
              enable = lib.mkEnableOption "DPI-bypassing transparent proxy";

              setupFirewall = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = "Set up firewall rules to redirect traffic to the proxy";
              };

              extraArgs = lib.mkOption {
                type = lib.types.str;
                default = "";
                example = "--split-positions 1";
                description = "Extra arguments to pass to the adpi binary";
              };
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.adpi = {
              description = "DPI-bypassing transparent proxy";
              after = [ "network.target" ];
              wantedBy = [ "multi-user.target" ];

              serviceConfig = {
                ExecStart = "${package}/bin/adpi ${cfg.extraArgs}";

                DynamicUser = true;
                User = "adpi";

                AmbientCapabilities = [
                  "CAP_NET_BIND_SERVICE"
                  "CAP_NET_ADMIN"
                ];
                CapabilityBoundingSet = [
                  "CAP_NET_BIND_SERVICE"
                  "CAP_NET_ADMIN"
                ];
              };
            };

            networking.nftables.tables.adpi-nat =
              lib.mkIf (cfg.setupFirewall && config.networking.nftables.enable)
                {
                  family = "inet";
                  content = ''
                    chain pre {
                      type nat hook prerouting priority dstnat; policy accept;
                      tcp dport { 80, 443 } meta mark != 1280 redirect to :1280
                    }

                    chain out {
                      type nat hook output priority mangle - 10; policy accept;
                      tcp dport { 80, 443 } meta mark != 1280 redirect to :1280
                    }
                  '';
                };

            networking.firewall.extraCommands =
              lib.mkIf (cfg.setupFirewall && !config.networking.nftables.enable)
                ''
                  ip46tables -t nat -A PREROUTING -p tcp -m multiport --dports 80,443 -m mark ! --mark 1280 -j REDIRECT --to-port 1280
                  ip46tables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -m mark ! --mark 1280 -j REDIRECT --to-port 1280
                '';
          };
        };
    };
}
