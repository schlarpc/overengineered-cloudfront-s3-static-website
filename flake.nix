{
  description = "overengineered-cloudfront-s3-static-website";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python3;
        application = python.pkgs.buildPythonApplication (with python.pkgs; {
          name = "overengineered-cloudfront-s3-static-website";
          src = pkgs.nix-gitignore.gitignoreSourcePure [ ] ./.;
          propagatedBuildInputs = with python.pkgs; [ awacs boto3 troposphere ];
          buildInputs = [ flit ];
          format = "pyproject";
        });
      in { defaultPackage = application; });
}
