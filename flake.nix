{
  inputs = {
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    systems.url = "github:nix-systems/default";
    git-hooks.url = "github:cachix/git-hooks.nix";
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pre-commit-hooks.follows = "git-hooks";
    };
  };

  nixConfig = {
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
    extra-substituters = "https://devenv.cachix.org";
  };

  outputs =
    {
      self,
      nixpkgs,
      devenv,
      systems,
      ...
    }@inputs:
    let
      forEachSystem = nixpkgs.lib.genAttrs (import systems);
    in
    {
      packages = forEachSystem (system: {
        devenv-up = self.devShells.${system}.default.config.procfileScript;
      });

      devShells = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        #lib = nixpkgs.lib;
        {
          default = devenv.lib.mkShell {
            inherit inputs pkgs;
            modules = [
              {
                name = "UDR";

                dotenv.enable = true;

                languages = {
                  c.enable = true;
                  cplusplus.enable = true;
                  python = {
                    enable = true; # 3.11 - revisit occasionally and make sure packages match
                    directory = "./tests";
                  };
                  shell.enable = true;
                  nix.enable = true;
                };

                pre-commit = {
                  hooks = {
                    # Linters & formatters
                    clang-format = {
                      enable = true;
                      types_or = [
                        "c"
                        "c++"
                      ];
                    };
                    black = {
                      enable = true;
                      types = [ "python" ];
                    };
                    isort = {
                      enable = true;
                      types = [ "python" ];
                    };
                    shellcheck = {
                      enable = true;
                      types = [ "shell" ];
                    };
                    shfmt = {
                      enable = true;
                      types = [ "shell" ];
                    };
                    checkmake = {
                      enable = true;
                      types = [ "makefile" ];
                    };
                    nixfmt-rfc-style = {
                      enable = true;
                      types = [ "nix" ];
                    };

                    # Basic git / shell / file checks
                    check-added-large-files.enable = true;
                    check-merge-conflicts.enable = true;
                    check-executables-have-shebangs.enable = true;
                    check-symlinks.enable = true;
                    end-of-file-fixer.enable = true; # No empty lines at end of file
                    trim-trailing-whitespace.enable = true; # At end of lines

                    # Protect you & me from ourselves
                    detect-private-keys.enable = true;
                  };
                };

                # https://devenv.sh/reference/options/
                packages = with pkgs; [
                  python311Packages.pip
                  python311Packages.pytest
                ];

                enterShell = ''
                  echo "Welcome to the UDR development environment \
                  Python, Pip, and PyTest are included in this \
                  environment to facilitate testing.  The standard \
                  environment (glibc, gcc, make) are also included. \
                  Pre-action Git Hooks included to promote code readability."
                '';
              }
            ];
          };
        }
      );
    };
}
