{
  description = "overengineered-cloudfront-s3-static-website";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python3;
        extraPyPkgs = with python.pkgs; rec {
          awacs = (buildPythonPackage rec {
            pname = "awacs";
            version = "2.0.2";
            src = fetchPypi {
              inherit pname version;
              hash = "sha256-AYE4wQ+C4Rc0ruf55//12/4SRd2vFdWSf2DzsW4BrX4=";
            };
          });
          troposphere = (buildPythonPackage rec {
            pname = "troposphere";
            version = "3.1.1";
            src = fetchPypi {
              inherit pname version;
              hash = "sha256-aDE8EZw+WtRX0qQfc5a6rdVFUfIhJoq5fUQTTxW9svM=";
            };
            propagatedBuildInputs = [ cfn-flip awacs ];
            doCheck = false; # tests not included on pypi
          });
        };
        application = python.pkgs.buildPythonApplication (with python.pkgs; {
          name = "overengineered-cloudfront-s3-static-website";
          src = pkgs.nix-gitignore.gitignoreSourcePure [ ] ./.;
          propagatedBuildInputs = with extraPyPkgs; [ awacs boto3 troposphere ];
          buildInputs = [ flit ];
          format = "pyproject";
        });
      in { defaultPackage = application; });
}
