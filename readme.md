##cDSCDockerSwarm

Management of Docker installation, version, swarm, configuration, and certificates on Windows Server 2016

### cDockerBinaries

Supports several binary sources, including the Microsoft Docker Provider
EE versioning is in place but untested thus far

If the running version is different than desired:  

1. The desired version is downloaded
2. Docker service is stopped
3. New binaries of docker and dockerd are extracted
4. Docker is started
 
example DSC configuration usage
```
cDockerBinaries dockerexe
{
	version = 17.06.0-ce
	DownloadChannel = 'Stable'
}
```
Will verify the installed version and and install if needed 17.06.0-ce from https://download.docker.com/win/static/stable/x86_64

**Parameters**  
DownloadChannel options:

 Stable: https://download.docker.com/win/static/stable/x86_64  
 Edge: https://download.docker.com/win/static/edge/x86_64  
 Test: https://download.docker.com/win/static/test/x86_64  
 Get: http://get.docker.com/builds/Windows/x86_64  
 DockerProject: https://master.dockerproject.org  

version should be a complete version as seen in:  
```
C:\> docker version  
<...>  
Server:  
 Version:      17.06.0-ce
```

###cDockerConfig

Builds and manages the Docker configuration in C:\ProgramData\docker\config\daemon.json

Example:
```
cDockerConfig DaemonJson
{
    Ensure = 'Present'
    DependsOn = '[cDockerBinaries]Docker'
    BaseConfigJson = '{ "experimental": true }'  
    RestartOnChange = $false
    ExposeAPI = $true
    InsecureRegistries = myregistry.contoso.com:5000
    Labels = "contoso.environment=dev","contoso.usage=internal"
}
```

Will Produce:
```
{
    "experimental":  true,
    "insecure-registries":  [
                                "myregistry.contoso.com:5000"
                            ],
    "labels":  [
                   "contoso.environment=dev",
                   "contoso.usage=internal"
               ],
    "hosts":  [
                  "tcp://0.0.0.0:2375",
                  "npipe://"
              ]
}

If RestartOnChange is set, it will restart the daemon after any change to the configuration

###cDockerSwarm

Manages the state of the swarm, and number of managers if desired. The worker tokens are pulled from the desired manager at the tine of joining. This may need to be adjusted when tls support is added

If SwarmManagement is set to Automatic, the configuration will query the current number of managers in the swarm, and join the node as a manager if the count is lower than the desired "ManagerCount"

Example:
```
cDockerSwarm Swarm {
    DependsOn = '[cDockerBinaries]Docker'
    SwarmMasterURI = '10.20.30.40:2377'
    SwarmMode = 'Active'
    ManagerCount = 3
    SwarmManagement = 'Automatic'
}
```

###cInsecureRegistryCert

Manages the certificate for a given local insecure registry that has been defined in cDockerConfig 

Example:
```
cInsecureRegistryCert ProdRegistry
{
    Ensure = 'Present'
    DependsOn = '[cDockerBinaries]Docker'
    registryURI = myregistry.contoso.com:5000
    Certificate = '-----BEGIN CERTIFICATE-----
......................................................
......................................................
......................................................

-----END CERTIFICATE-----'
}
```