# sbom-manager

The SBOM Manager is a free, open source tool to help you manage a collection of SBOMs  (Software Bill of Materials).

The tool has two main modes of operation:

1. A repository which maintains the set of components which have been included as part of a release of  a software product.
2. Tools for quering the inclusion of specific products in a project development to answer some commmon use cases.

It is intended to be used as part of a continuous integration system to enable regular records of SBOMs to be maintained 
and also to support security audit needs to determine if a particular component (and version) has been used.

## Installation

To install, just clone the repo.

The tool requires Python 3 (3.7+).

## Usage

`python sbom.py [-h] [-a ADD_FILE] [-t {spdx,cyclonedx,csv,dir}]
                [-l {all,sbom,module}] [-m MODULE] [-d DESCRIPTION]
                [-p PROJECT] [-s] [-q]
                [-L {debug,info,warning,error,critical}] [-o OUTPUT_FILE]
                [-f {csv,console}] [-C CONFIG] [-I] [-V]

The SBOM Manager manages SBOMs (Software Bill of Materials) to allow
searching for modules and scanning for vulnerabilities.

optional arguments:
  -h, --help            show this help message and exit
  -C CONFIG, --config CONFIG
                        Name of config file
  -I, --initialise      Initialise SBOM manager
  -V, --version         show program's version number and exit

Input:
  -a ADD_FILE, --add ADD_FILE
                        SBOM file to be added
  -t {spdx,cyclonedx,csv,dir}, --sbom-type {spdx,cyclonedx,csv,dir}
                        SBOM file type
  -l {all,sbom,module}, --list {all,sbom,module}
                        list SBOMs (default all)
  -m MODULE, --module MODULE
                        Find module in SBOMs
  -d DESCRIPTION, --description DESCRIPTION
                        Description of SBOM file
  -p PROJECT, --project PROJECT
                        Project name
  -s, --scan            Scan SBOMs for vulnerabilities

Output:
  -q, --quiet           Suppress output
  -L {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}
                        Log level (default: info)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output filename (default: output to stdout)
  -f {csv,console}, --format {csv,console}
                        Output format (default: console)`
						
## Operation

To start using sbom-manager, a repository needs to be created.

`python sbom.py -I`

You can also used this command if the repository needs to be reset, e.g. following an upgrade to the tool.

Once a repository is created, SBOM files need to be added. The following types of SBOMs are supported:

  - SPDX (Tag/Value format compatible with version SPDX 2.2).
  - CycloneDX (XML format).
  - CSV where the file is a set of lines containing vendor, product, version entries.
  - DIR which is a file containing a directory listing of filenames. To create a directory file, the following command can be used `find . -type f > <filename>`

The type of SBOM to be added is specified using the `--type` parameter. 

The `--project` parameter is intended to be used to allow for filtering of SBOMs when querying for data. 

If the `--description` parameter is not specified when adding SBOM files, a default value of 'Not Specified' is assumed. This parameter is typically
intended to be used to record build versions of a project.

Invalid entries in an SBOM file will be silently ignored although specifying `--Log debug` may provide some insight into what is being processed.

The `--module` option is used to query the repostiry for the existence of a particular module. This may optionally be filtered by project name. The
name of the module is assumed to be wildcard so that a search for a module called 'lib' will find all modules which contain the sequence 'lib'.

Note that the `--scan` and `--config` options do not do anything currently. 

## Licence

Licenced under the MIT Licence

## Limitations

This tool is meant to support software development and security audit functions. However the usefulness of the tool is dependent on the SBOM data
which is provided to the tool. Unfortunately, the tool is unable to determine the validity or completeness of such a SBOM file; users of the tool
are therefore reminded that they should assert the quality of the data before adding any data to the tool. 

## Use Cases

Typical use cases for the tool are:

  - Is my organisation impacted by vulnerability Z with component X?
  - Does my project use version X of component Y?
  - What version(s) of component Y is being used?
  - What vulnerabilities exist within my product? And what needs to be fixed?

Is my organisation impacted by vulnerability Z with component X?

`python sbom.py -–module <xx>`

Does my project use version X of component Y?

`python sbom.py –p <project name> -m <product name> | grep <version>`

What version(s) of component Y is being used?

`python sbom.py –p <project name> -m <product name>`

What vulnerabilities exist within my product? And what needs to be fixed?

`python sbom.py –p <project name> --scan`

This is currently not implemented.

## To Do

The following are items to be completed before an initial release:

  - Create config file
  - Link to vulnerability scanner
  - Generate SPDXLite files for CSV and Directory entries

## Feedback & Contributions

Bugs and feature requests can be made via GitHub Issues. Take care when providing output to make sure you are not
disclosing security issues in other products.

Pull requests are via git.

## Security Issues

Security issues with the tool itself can be reported using GitHub Issues.

If in the course of using this tool you discover a security issue with someone else's code, please disclose responsibly to the appropriate party.
