# SBOM Manager

The SBOM Manager is a free, open source tool to help manage a collection of SBOMs(Software Bill of Materials) in a number of formats including
[SPDX](https://www.spdx.org) and [CycloneDX](https://www.cyclonedx.org).

The tool has two modes of operation:

1. A repository which maintains the set of components which have been included as part of a release or build of a software product.
2. Tools for querying the inclusion of specific products in a project development to answer some common use cases.

It is intended to be used as part of a continuous integration system to enable regular records of SBOMs to be maintained 
and also to support security audit needs to determine if a particular component (and version) has been used.

## Installation

To install use the following command:

`pip install sbom-manager`

Alternatively, just clone the repo and install dependencies using the following command:

`pip install -U -r requirements.txt`

The tool requires Python 3 (3.7+). It is recommended to use a virtual python environment especially 
if you are using different versions of python. `virtualenv` is a tool for setting up virtual python environments which
allows you to have all the dependencies for the tool set up in a single environment, or have different environments set
up for testing using different versions of Python.

## Usage

```
sbom-manager [-h] [-I] [-a ADD_FILE] [-t {spdx,cyclonedx,csv,dir}]
                [-l {all,sbom,module}] [-m MODULE] [-d DESCRIPTION]
                [-p PROJECT] [-s] [--history] [--export EXPORT] [--import IMPORT]
                [-q] [-L {debug,info,warning,error,critical}] [-o OUTPUT_FILE]
                [-f {csv,console}] [-C CONFIG] [-V]
```

```
options:
  -h, --help            show this help message and exit
  -C CONFIG, --config CONFIG
                        Name of config file
  -V, --version         show program's version number and exit

Input:
  -I, --initialise      Initialise SBOM manager
  -a ADD_FILE, --add ADD_FILE
                        SBOM file to be added
  -t {spdx,cyclonedx,csv,dir}, --sbom-type {spdx,cyclonedx,csv,dir}
                        SBOM file type
  -l {all,sbom,module}, --list {all,sbom,module}
                        list contents of SBOM
  -m MODULE, --module MODULE
                        Find module in SBOMs
  -d DESCRIPTION, --description DESCRIPTION
                        Description of SBOM file
  -p PROJECT, --project PROJECT
                        Project name
  -s, --scan            Scan SBOMs for vulnerabilities
  --history             Include file history


Data:
  --export EXPORT       export database filename
  --import IMPORT       import database filename

Output:
  -q, --quiet           Suppress output
  -L {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}
                        Log level (default: info)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output filename (default: output to stdout)
  -f {csv,console}, --format {csv,console}
                        Output format (default: console)

Please report issues responsibly!

```
						
## Operation

To start using the tool, a repository needs to be created.

`sbom-manager -I`

You can also use this command if the repository needs to be reset, e.g. following an upgrade to the tool.

Once a repository is created, SBOM files can be added. The following types of SBOMs are supported:

  - SPDX (Tag/Value format or JSON format compatible with version SPDX 2.3).
  - CycloneDX (XML format or JSON format compatible with CycloneDX version 1.4).
  - CSV where the file is a set of lines containing vendor, product, version entries.
  - DIR which is a file containing a directory listing of filenames. To create a directory file on a Linux based system, the following command can be used `find . -type f > dir_list`

The type of SBOM to be added is specified using the `--type` parameter. JSON formatted SBOMs should have a `.json` file extension.

The `--project` parameter is intended to be used to allow for filtering of SBOMs when querying for data. 

If the `--description` parameter is not specified when adding SBOM files, a default value of 'Not Specified' is assumed. This parameter is typically
intended to be used to record build versions of a project.

Invalid entries in an SBOM file will be silently ignored although specifying `--Log debug` may provide some insight into what is being processed.

The `--module` option is used to query the repostory for the existence of a particular module. This may optionally be filtered by project name. The
name of the module is assumed to be wildcard so that a search for a module called 'lib' will find all modules which contain the sequence 'lib'.

The `--list` option is used to report the contents of the repository. The default behaviour is to just show the latest updates for
the specified SBOMs or module. The `--history` option can be used to show all updates.

The `--config` option is used to specify the [configuration file](#configuration-file) to be used. This is required when the  `--scan` is specified.

The `--scan` option is used to scan a SBOM for vulnerabilities. This requires the use of an external vulnerability scanner which
takes a spdx tag value file as input. The vulnerability scanner to be used in specified in the [configuration file](#configuration-file)
specified in the `--config` option.

The `--output-file` and `--format` options can be used to control the formatting and destination of the output generated by the tool. The
default is to report to the console but can be stored in a file (specified using `--output-file` option). The format of the output can be changed using 
the `--format` option which may be useful if the output is to be used as an input by another tool.

The `--export` and `--import` options can be used to archive a copy of the repository or to restore a repository,


## Configuration File

A configuration file is used to specify a number of options for the tool. The following is an example file.

```
# SBOM configuration file
[data]
# Use default value if not specified
#location = ""
[scan]
application = cve-bin-tool
# Options are dependent on application. Typically used to define output format or debug levels
options = --sbom spdx --sbom-file
```

Comments are indicated by lines starting with '#'. All content is ignored.

The options are grouped into two sections **data** and **scan**.

The following options are supported:

- *location* is within the data section and used to specify the location of the repository to store the SBOM files. A default location is used if this is not specified.

- *application* is within the scan section and is used to specify the name of the application to be used with the `--scan` option. A fully qualified path may need to be specified
depending on the system configuration.

- *options* is within the scan section and is used to specify any application specific options to be used when scanning a SBOM file for vulnerabilities. The SBOM file name to be scanned
will be automatically appended to the options.

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

### Is my organisation impacted by vulnerability Z with component X?

This is simply addressed by looking for the component in the set of SBOMs.

`sbom-manager -–module <module name>`

This could also be filtered on a project basis.

If the component is found then further analysis would be required to match the specific vulnerability with the version(s) of the component.

### Does my project use version X of component Y?

This can be achieved by looking for the component and filtering on the version of the component.

`sbom-manager –-project <project name> -–module <module name> | grep <version>`

### What version(s) of component Y is being used?

To look across all projects

`sbom-manager -–module <product name>`

This can also be filtered on a project basis.

`sbom-manager –-project <project name> -–module <module name>`

### What vulnerabilities exist within my product? And what needs to be fixed?

This requires the use of an external vulnerability scanner which takes a spdx tag value SBOM file as input. The path
to the vulnerability scanner is specified in a configuration file as well as any tool specific parameters to be
specified (e.g. to filter on severity value).

`sbom-manager –-project <project name> --scan`

This will report a set of vulnerabilities (if any) against each of the components defined within the SBOM file.

Unfortunately, determining whether each of the reported vulnerabilities needs to be fixed is beyond the capability of this tool!

## Feedback and Contributions

Bugs and feature requests can be made via GitHub Issues. Take care when providing output to make sure you are not
disclosing security issues in other products.
