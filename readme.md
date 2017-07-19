## cDSCDockerSwarm

Management of Docker installation, version, swarm, configuration, and certificates on Windows Server 2016    
Please see [my Blog on this module](http://www.pscripted.com/docker-dsc/)

Available from the PowerShell Gallery, install with:
```
Install-Module -Name cDSCDockerSwarm
```

### Pre-recs and other thoughts

The firewall must be either disabled, or ports added as exceptions to allow a swarm to communicate, the module does not take care of it. It is not in the Example configurations, but I have been using xDSCFirewall in my testing environment to take care of it. 

Containers Windows Feature. The EE Docker provider will attempt to install the Containers feature, however I like explicity installing it in the configuration anyway. The CE installation does not attempt to feature installation, it must be installed beforehand. 

### cDockerBinaries

Supports several binary sources, including the Microsoft Docker Provider  
EE support is a work in progress, there have been some issues detecting that the correct provider is installed.

If the running version is different than desired:  

1. The desired version is downloaded
2. Docker service is stopped
3. New binaries of docker and dockerd are extracted
4. Docker is started
 
example DSC configuration usage
```
 cDockerBinaries Docker
       {
            Ensure = 'Present'
            DependsOn = '[WindowsFeature]Containers
            version = '17.06.0-ce'
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
 EE: Use Microsoft Docker provider

version should be a complete version as seen in:  
```
C:\> docker version  
<...>  
Server:  
 Version:      17.06.0-ce
```
### cDockerTLSAutoEnrollment

if Esnure is set to Present, when the designated enrollment server runs its configuration it will download a container to create all the certificates for the swarm. More details on the container can be found at [Docker Hub](https://hub.docker.com/r/pscripted/dsc-dockerswarm-tls/)

This container will create:    
 A CA in C:\DockerTLSCA with a passphrase protected private key ("cdscdockerswarm")
 A host certificate for Docker with private key
 A client Certificate for the running user

The other nodes will access the container as a web service to receive their signed certificates.

Additional clients (workstations, other users on the servers, etc) can use the Install-cDSCSwarmTLSCert cmdlet that is included in the module to request client keys and install them in the current users cert directory.

Once all certificates generated have been set you can disable set this resource to Absent to prevent new key generation.

While this resource will create all the necessary certificates, telling the configuration to set up TLS must be set as well in the cDockerConfig resource.

```
cDockerTLSAutoEnrollment Enrollment 
    {
        Ensure = 'Present'
        EnrollmentServer = "102.168.10.20"
        DependsOn = '[cDockerBinaries]Docker'
    }
```
### cDockerConfig

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
    EnableTLS = $true
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
              ],
    "tlscacert": "C:\\ProgramData\\docker\\certs.d\\ca.pem",
    "tlscert": "C:\\ProgramData\\docker\\certs.d\\cert.pem",
    "tlskey": "C:\\ProgramData\\docker\\certs.d\\key.pem",
    "tlsverify": true
}
```
If RestartOnChange is set, it will restart the daemon after any change to the 
ExposeAPI will allow named pipe connections, as well as a default binding on all interfaces for communication. This must be enabled for a swarm setup.

### cDockerSwarm

Manages the state of the swarm, and number of managers if desired. The worker tokens are pulled from the desired manager at the tine of joining. This may need to be adjusted when tls support is added

SwarmManagerURI should be the desired first manager. The same DSC Configuration can be used on the manager node at the same time as other nodes, the configuration will initialize the swarm, and the worker nodes will attempt a few retries to connect to the manager while it initializes.

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

### cInsecureRegistryCert

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