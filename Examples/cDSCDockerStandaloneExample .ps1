configuration TestDockerSwarm
{

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName cDSCDockerSwarm -ModuleVersion 0.9.2
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
MIIDGzCCAgOgAwIBAgIJAODTn5nU1n6/MA0GCSqGSIb3DQEBBQUAMCQxIjAgBgNV
BAMMGWltYWdlcmVnaXN0cnkuY29udG9zby5jb20wHhcNMTcwNzE0MDEwMDA1WhcN
MjcwNzEyMDEwMDA1WjAkMSIwIAYDVQQDDBlpbWFnZXJlZ2lzdHJ5LmNvbnRvc28u
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwn7hLsaq40PaJ4iV
VTr37g/VB8h4sPebX/sj2wKtUX4Kb8wmBkiDG04B0hVsjvPOJT1CfT+iWVM9Jn1V
KrfdMk6qBGN1WX9TejfyC3Czdd3T0Ql+MVPFKtJHcmjAuuOVvA7BYfymWBTBqAZ4
fVYBBVIHH02P4RYxqZzGBhe+4YYvsLwKRIBqvW58XLSnmBd0muiqbqZIo19znqNO
BH79+Ta/w12jB+jTXTRR5Po75KlF5Yophn1wUnOw9M4UdfQVGkpPAJRwyDRNedbw
eqzoc972CX9UtqjwFQKyWhmBAmpQXGtljt5ueAcv56YJ10/pBA4EP+HQIdypdyD4
NniznwIDAQABo1AwTjAdBgNVHQ4EFgQUTZgW9lOq2qvzS9HYlZ7cEpghfUQwHwYD
VR0jBBgwFoAUTZgW9lOq2qvzS9HYlZ7cEpghfUQwDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQUFAAOCAQEAvJQh9LekAtamITCGRnbtPuknA7JvNfm1zLphrc4+qGjB
qJhew2Sa732yuSbMR133QBeh5TcbMlkRzgYCAXc6BtD3qMkG/lF8PleBycc5QIMq
5qMiR6ASnhigbLbwx7bHAt/tW/8jpGFIBAEJhKf+oQSCG6+K/CcdFoafvofQ5Ncc
uuqX35bDg4ZToN060ITYhp5BWDN9vhCeUwKrj8pgeUNINjICFGaEohaBvfq1Xi/T
eI3TuM4iJ8pdFGtHpNHnSV4Z/aRlBWonsHC2YrGnRQ3qBu+29TpPgxRBNuk0mv8O
BzKqMFhy29cU/Rjrvrk4BBEeg0dFSF0zlC1fXWeWRA==
-----END CERTIFICATE-----'
       }

       cDockerConfig Config
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