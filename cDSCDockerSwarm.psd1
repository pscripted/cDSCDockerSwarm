#
# Module manifest for module 'cDockerBinaries'
#
# Generated by: Matt Sollie
#
# Generated on: 6/29/2017
#

@{

RootModule = 'cDSCDockerSwarm.psm1'
ModuleVersion = '0.8'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '692cae80-eb9f-461a-93ea-c44aed79cc4c'

Author = 'Matt Sollie'
Copyright = '(c) 2017 matt sollie. All rights reserved.'
Description = 'DSC Module for Docker and Swarm management'

# DSC resources to export from this module
DscResourcesToExport = @('cDockerBinaries', 'cDockerConfig','cInsecureRegistryCert','cDockerSwarm')

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/pscripted/cDSCDockerSwarm'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
HelpInfoURI = 'https://github.com/pscripted/cDSCDockerSwarm'


}

