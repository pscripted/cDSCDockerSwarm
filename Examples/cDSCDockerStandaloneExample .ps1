configuration TestDockerSwarm
{

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName cDSCDockerSwarm
    node ("localhost")
    {
     WindowsFeature RSatAD
        {
            Ensure = "Present"
            Name   = "RSAT-AD-Powershell"
        }

         WindowsFeature ContainerInstall
        {
            Ensure = "Present"
            Name   = "Containers"
        }

       cDockerBinaries Docker
       {
            Ensure = 'Present'
            DependsOn = '[WindowsFeature]ContainerInstall'
            version = '17.06.0-ce'
            DownloadChannel = 'Stable'
       }


       cInsecureRegistryCert registry
       {
            Ensure = 'Present'
            DependsOn = '[cDockerBinaries]Docker'
            registryURI = 'myregistry:5000'
            Certificate = '-----BEGIN CERTIFICATE-----
            -----------------------------------
-----END CERTIFICATE-----'
       }

       cDockerConfig test
       {
            Ensure = 'Present'
            DependsOn = '[cDockerBinaries]Docker'
            RestartOnChange = $true
            ExposeAPI = $true
            InsecureRegistries = 'myregistry:5000'
            Labels = "my.environment=test", "my.winver=core"
        }
    }
}