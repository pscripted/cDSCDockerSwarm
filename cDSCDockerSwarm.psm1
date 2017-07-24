# Defines the values for the resource's Ensure property.
enum Ensure
{
    # The resource must be absent.    
    Absent
    # The resource must be present.    
    Present
}

enum Swarm
{
    # The Swarm must be active   
    Active
    # The Swarm must be inactive
    Inactive
}

enum SwarmManagement
{
    # Manage Manager Count  
    Automatic
    # Only join as worker
    WorkerOnly
}

enum DownloadChannel
{
    Stable
    Edge
    Test
    Get
    DockerProject
    EE
}

# [DscResource()] indicates the class is a DSC resource.
[DscResource()]
class cDockerBinaries
{
    #Ensure binaries are installed or not
    [DscProperty(Key)]
    [Ensure]$Ensure

    #Docker Version in the form of "17.06.0-ce"
    [DscProperty()]
    [string]$version

    #Download Channel for different CE Builds, or EE for microsoft provided
    [DscProperty()]
    [DownloadChannel]$DownloadChannel

    # Sets the desired state of the resource.
    [void] Set()
    {
        $dlURL =""
        switch ($this.DownloadChannel) {
            Stable {$dlURL = "https://download.docker.com/win/static/stable/x86_64"}
            Edge {$dlURL = "https://download.docker.com/win/static/edge/x86_64"}
            Test {$dlURL = "https://download.docker.com/win/static/test/x86_64"}
            Get {$dlURL = "http://get.docker.com/builds/Windows/x86_64"}
            DockerProject {$dlURL = "https://master.dockerproject.org"}
            EE {}
        }
        $GetVersion = $this.version

        if ($this.DownloadChannel -eq "EE") {
            #Use DockerMsftProvider
            Write-Verbose "Using DockerMsftProvider"

            if ((Get-PackageProvider -ListAvailable).Name -notcontains "NuGet") {
                Write-Verbose "Installing NuGet"
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            }
            if (!(get-module DockerMsftProvider -listavailable)) {
                Write-Verbose "Installing DockerMsftProvider "
                Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
            }     
            #Attempt installation         
            try {
                Install-Package -Name docker -RequiredVersion $this.version -ProviderName DockerMsftProvider -Force -verbose            
            }
            catch {
                Write-Verbose "Could not install Docker $($this.version); $($_.Exception)"                    
            }
        }
        else {
            Write-Verbose "Using $($this.DownloadChannel) channel URL $dlURL"
            Write-Verbose "Updating Docker binaries from $($dlURL)/docker-$GetVersion.zip"

            Invoke-WebRequest "$dlURL/docker-$GetVersion.zip" -UseBasicParsing -OutFile "$($env:temp)\docker.zip"
            $DockerRegistered = (Get-Service).Name -contains "Docker"

            if ($DockerRegistered) {
                Stop-Service docker
                start-sleep 2
            }

            Expand-Archive -Path "$($env:temp)\docker.zip" -DestinationPath $Env:ProgramFiles -Force
            Remove-Item -Force "$($env:temp)\docker.zip"      
            
            if (!$DockerRegistered) {
                Write-Verbose "Registering Docker Service"
                $Env:Path += ";$($Env:ProgramFiles)\docker"
                [Environment]::SetEnvironmentVariable('PATH', $env:Path, 'Machine')
                . "$($Env:ProgramFiles)\docker\dockerd.exe" --register-service 
            }
        }
        Write-Verbose "Starting Docker Service"
        Start-Service docker  
    }        
    
    # Tests if the resource is in the desired state.
    [bool] Test()
    {        
        if ($this.DownloadChannel -eq "EE") {
            try {
                $dockerPackage = Get-Package docker -ProviderName DockerMsftProvider -errorAction Stop
                if ($dockerPackage.version -match $this.version) {
                    Write-Verbose "Correct Version Installed"
                    return $true
                }
                else {                
                    Write-Verbose "Wrong Version of Docker is installed: $($dockerPackage.version) should be $($this.version)"
                    return $false
                }
            }
            catch {
                Write-Verbose "Failed to find docker package"
                return $false
            }            
        }
        else {
            $service = (Get-Service).Name -contains "Docker"
            $exeExists = Test-Path $env:ProgramFiles\docker\dockerd.exe
            if ($exeExists){ 
                $CurrentVersion = (Get-Item $env:ProgramFiles\docker\dockerd.exe).VersionInfo.ProductVersion 
            }
            else {
                $CurrentVersion = $null    
            }

            if ($service -and ($CurrentVersion -eq $this.version)) {               
                Write-Verbose "desired version $($this.version) is installed"
                return $true
            }
            elseif ($service -and ($CurrentVersion -ne $this.version)) {
                Write-Verbose "Desired version $($this.version) is not installed"
                return $false
            }            
            else {
                Write-Verbose "Docker is not installed"
                return $false
            }
        }
    }    
    # Gets the resource's current state.
    [cDockerBinaries] Get()
    {        
        $exeExists = Test-Path $env:ProgramFiles\docker\dockerd.exe
        $DockerRegistered = (Get-Service).Name -contains "Docker"
        if ($exeExists -and $DockerRegistered) {
            $this.Ensure = [Ensure]::Present
            $this.version = (Get-Item $env:ProgramFiles\docker\dockerd.exe).VersionInfo.ProductVersion
        }
        else {
            $this.Ensure = [Ensure]::Absent
            $this.version = $null
        }
        return $this
    }    
}

[DscResource()]
class cInsecureRegistryCert
{
    # Registry URI in format "registry:5000"
    [DscProperty(Key)]
    [string]$registryURI

    #Certificate text or read content from file
    [DscProperty(Mandatory)]
    [string]$Certificate

    #Ensure Present or Absent
    [DscProperty(Mandatory)]
    [Ensure] $ensure

    # Sets the desired state of the resource.
    [void] Set()
    {
        $CertPath = "$($env:ProgramData)\docker\certs.d\$($this.registryURI -replace ':','')"

        if ($this.ensure -eq [ensure]::Present) {
            Write-Verbose "Writing Certificate"
            if (-not (Test-Path $CertPath)) {
               mkdir $CertPath
            }
            $this.Certificate | Out-File "$CertPath\ca.crt" -Encoding ascii -Force
        }
        else {
            if (Test-Path $CertPath) {
                Write-Verbose "Removing Certificate"
                Remove-Item $CertPath -Force -Recurse
            }
        }
    }        
    
    # Tests if the resource is in the desired state.
    [bool] Test()
    {
        $CertPath = "$($env:ProgramData)\docker\certs.d\$($this.registryURI -replace ':','')"
        if ($this.ensure -eq [ensure]::Present) {
            if(test-path "$CertPath\ca.crt") {
                try {
                    $currentCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $currentCert.Import("$CertPath\ca.crt")
                }
                catch {
                    Write-Verbose "Invalid Current Cert; could not be imported to test"
                    return $false
                }                    
                
                try {                    
                $enc = [system.Text.Encoding]::UTF8
                $desiredCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $desiredCert.Import($enc.GetBytes($this.Certificate))
                  }
                catch {
                    Write-Verbose "Invalid Desired Certificate defined in configuration; could not be imported to test"
                    return $false
                }   
                                   
                if($currentCert.Thumbprint -eq $desiredCert.Thumbprint) {

                Write-Verbose "valid certificate installed"
                return $true
                }
                else {
                    write-verbose "Wrong registry Certificate"                                    
                    return $false
                }
            }
            else {
                Write-Verbose "Missing CA Cert for Registry"
                return $false
            }
        }
        else {
            if(test-path "$($env:ProgramData)\docker\certs.d\$($this.registryURI -replace ':','')\ca.crt") {
                Write-Verbose "CA Cert for Registry Exists that should not"
                return $false    
            }
            else {
                return $true
            }
        }
    }    
    # Gets the resource's current state.
    [cInsecureRegistryCert] Get()
    {        
        if(test-path "$($env:ProgramData)\docker\certs.d\$($this.registryURI -replace ':','')\ca.crt") {
            $this.ensure = [ensure]::Present
        }
        else {
            $this.ensure = [ensure]::Absent
        }
        return $this
    }
  
}

[DscResource()]
class cDockerConfig
{

    #Ensure present or absent
    [DscProperty(Key)]
    [Ensure]$Ensure

    #JSON format string of general configuration opstions, not including labels, hosts, and registries
    [DscProperty()]
    [string]$BaseConfigJson='{}'

    #Array of registries to be added to the configuration
    [DscProperty()]
    [string[]] $InsecureRegistries

    #Array of labels to be added to the configuration
    [DscProperty()]
    [string[]] $Labels

    #Daemon binings, defaults to all interfaces. Specify in format of 'tcp://0.0.0.0:2375'
    [DscProperty()]
    [string]$DaemonBinding

    #Adds named pipe and TCP bindings to configuration, allowing external access. This is required for Swarm mode
    [DscProperty()]
    [boolean] $ExposeAPI
    
    #Restart docker on any chane of the configuration
    [DscProperty()]
    [boolean] $RestartOnChange

    #Enable TLS
    [DscProperty()]
    [bool]$EnableTLS=$false

    # Sets the desired state of the resource.
    [void] Set()
    {    
        if ($this.Ensure -eq [Ensure]::Present) {
            
            $pendingConfiguration = $this.GetPendingConfiguration()

            #Does a config exist at all?
            $ConfigExists = $this.ConfigExists()
            Write-Verbose "Config Exists: $ConfigExists" 
            #Write Configuration
            $pendingConfiguration |  Out-File "$($env:ProgramData)\docker\config\daemon.json" -Encoding ascii -Force

            #Restart docker service if the configuration changed, or if this is the initial configuration
            if ($this.RestartOnChange -or !($ConfigExists)) {
                Write-Verbose "Restarting the Docker service"
                Restart-Service Docker
                start-sleep 5
            }
        }
        else {
            Remove-Item "$($env:ProgramData)\docker\config\daemon.json" -Force
        }     
    }        
    
    # Tests if the resource is in the desired state.
    [bool] Test()
    {   
        if ($this.Ensure -eq [Ensure]::Present) {     
            if($this.ConfigExists()){            
			    $currentConfiguration = Get-Content "$($env:ProgramData)\docker\config\daemon.json" -raw
                $pendingConfigurationJS = $this.GetPendingConfiguration() | Out-String                

                if ($currentConfiguration -eq $pendingConfigurationJS) {
                    Write-Verbose "Configuration Matches"
                    return $true
                }
                else{
                    Write-Verbose "Configuration Does not Match"
                    return $false
                }
		    }
		    else{
                Write-Verbose "Missing daemon.json"
			    return $false
		    }
        }
        else { #Make sure the config is absent
            if($this.ConfigExists()){
                Write-Verbose "daemon.json Exists but should not"
                return $false
              }
            else {
             Write-Verbose "daemon.json does not exist"
                return $true
            }
        }

		return $false
    }    
    # Gets the resource's current state.
    [cDockerConfig] Get()
    {   
        $ConfigExists = $this.ConfigExists()    
        if($ConfigExists){            
            $currentConfiguration = Get-Content "$($env:ProgramData)\docker\config\daemon.json" -raw
            $pendingConfigurationJS = $this.GetPendingConfiguration() | Out-String                

            if ($currentConfiguration -eq $pendingConfigurationJS) {
                $this.Ensure = [ensure]::Present
            }
            else {
                $this.Ensure = [ensure]::Absent
            }
        }
        else {
            $this.Ensure = [ensure]::Absent
        }
        return $this
     }

     [bool]ConfigExists() {
       if (Test-Path "$($env:ProgramData)\docker\config\daemon.json") {
                return $true
            }
            else {
                return $false
            }
     }

     [string]GetPendingConfiguration() {
     
        $pendingConfiguration = $this.BaseConfigJson | ConvertFrom-json

        if ($this.InsecureRegistries) {
            $pendingConfiguration | Add-Member -Name "insecure-registries" -Value  $this.InsecureRegistries -MemberType NoteProperty
        }
        if ($this.Labels) {
            $pendingConfiguration | Add-Member -Name "labels" -Value $this.Labels -MemberType NoteProperty
        }

        $CertExists = Test-Path $env:ALLUSERSPROFILE\docker\certs.d\cert.pem
        $KeyExists = Test-Path $env:ALLUSERSPROFILE\docker\certs.d\key.pem
        if ($this.EnableTLS -and $CertExists -and $KeyExists) {
            #Add TLS                 
            $pendingConfiguration | Add-Member -MemberType NoteProperty -Name  "tlscacert" -Value "C:\ProgramData\docker\certs.d\ca.pem"
            $pendingConfiguration | Add-Member -MemberType NoteProperty -Name  "tlscert" -Value "C:\ProgramData\docker\certs.d\cert.pem"
            $pendingConfiguration | Add-Member -MemberType NoteProperty -Name  "tlskey" -Value "C:\ProgramData\docker\certs.d\key.pem"
            $pendingConfiguration | Add-Member -MemberType NoteProperty -Name  "tlsverify" -Value $true     
            #Adjust port for TLS
            if($this.exposeApi -eq $true){
                if ($this.DaemonBinding) {
                    $binding = $this.DaemonBinding            
                }
                else {
                    $binding = "tcp://0.0.0.0:2376"
                }
			    $pendingConfiguration | Add-Member -Name "hosts" -MemberType NoteProperty -Value @($binding, "npipe://")
            }       
        }
        else{
            if($this.exposeApi -eq $true){
                if ($this.DaemonBinding) {
                    $binding = $this.DaemonBinding            
                }
                else {
                    $binding = "tcp://0.0.0.0:2375"
                }
			    $pendingConfiguration | Add-Member -Name "hosts" -MemberType NoteProperty -Value @($binding, "npipe://")
            }
        }

        return $pendingConfiguration | ConvertTo-Json
     }
    

}


# [DscResource()] indicates the class is a DSC resource.
[DscResource()]
class cDockerSwarm
{

    #Swarm Master URl in the format of "10.10.10.10:2377"
    [DscProperty(Key)]
    [string]$SwarmMasterURI

    #Activate swarm mode on the host and connect to swarm master. Must be Active or Inactive
    [DscProperty(Mandatory)]
    [Swarm] $SwarmMode

    #Number of managers to attempt of SwarmManagement is automatic. The nodes will join as managers until the number specified is met. 
    [DscProperty()]
    [int] $ManagerCount=3

    #Automatic will manage the number of managers in the swarm. WorkerOnly will join only as worker nodes
    [DscProperty(Mandatory)]
    [SwarmManagement]$SwarmManagement

    # Sets the desired state of the resource.
    [void] Set()
    {    
        Write-Verbose "Using Swarm Master: $($this.SwarmMasterURI)"
        $SwarmDockerHost = $($this.SwarmMasterURI).Split(':')[0]
        $SwarmManagerIsMe = (Get-NetIPAddress).IPAddress -contains $SwarmDockerHost
        Write-Verbose "Getting Local Docker info"

        $LocalInfo = $this.GetLocalDockerInfo()
        
        Write-Verbose "Getting Swarm info from $SwarmDockerHost"
        if ((test-netconnection $SwarmDockerHost -Port 2375).tcpTestSucceeded) {
            $swarmConnString = $SwarmDockerHost
            $tls = $null
        }
        elseif ((test-netconnection $SwarmDockerHost -Port 2376).tcpTestSucceeded) {
            $swarmConnString = "$($SwarmDockerHost):2376"
            $tls = "--tlsverify"
        }
        else {
            write-error "no connection to remote swarm manager"
        }
        #Random seed to sleep to get better distribution, and prevent too many managers.
        Start-Sleep (get-random -Minimum 0 -Maximum 15)
        $SwarmInfo = . "$($Env:ProgramFiles)\docker\docker.exe" -H $swarmConnString $tls info -f '{{ json .Swarm }}' | ConvertFrom-Json
        $managers = $SwarmInfo.managers
        
        if ($LocalInfo.Swarm.LocalNodeState -eq "active") {
            $InRightSwarm = $LocalInfo.Swarm.RemoteManagers.Addr -contains $this.SwarmMasterURI
            if (!$InRightSwarm) {
                Write-Verbose "Server is in the wrong swarm; leaving"
                . "$($Env:ProgramFiles)\docker\docker.exe" swarm leave -f
            }
            elseif ($this.SwarmMode -eq [Swarm]::Inactive) {
                Write-Verbose "Server is in the a swarm and should be inactive; leaving"
			    . "$($Env:ProgramFiles)\docker\docker.exe" swarm leave -f
		    }
            elseif (($this.SwarmMode -eq [Swarm]::Active) -and ($managers -lt $this.ManagerCount)) {
                . "$($Env:ProgramFiles)\docker\docker.exe" -H $swarmConnString $tls node promote $env:COMPUTERNAME
            }
        }
        elseif ($this.SwarmMode -eq [Swarm]::Active) {
            
            if ($SwarmManagerIsMe) {
                Write-Verbose "Creating a new Swarm"
                . "$($Env:ProgramFiles)\docker\docker.exe" swarm init --advertise-addr $this.SwarmMasterURI
            }
            elseif (($this.SwarmManagement -eq [SwarmManagement]::Automatic) -and ($managers -lt $this.ManagerCount)) {
                Write-Verbose "Joining the Swarm as a manager"
                $this.JoinSwarm($swarmConnString, $tls, "manager")
            }
            else {
                Write-Verbose "Joining the Swarm as a worker"
                $this.JoinSwarm($swarmConnString, $tls,"worker")
            }
        }        
		
    }        
    
    # Tests if the resource is in the desired state.
    [bool] Test()
    {        
            $LocalInfo = $this.GetLocalDockerInfo()
            
			if ($LocalInfo.Swarm.LocalNodeState  -eq "active" -and ($this.SwarmMode -eq [Swarm]::Active)) {
                Write-Verbose "Swarm is Active"
                #Test for swarm membership                
                $InRightSwarm = $LocalInfo.Swarm.RemoteManagers.Addr -contains $this.SwarmMasterURI
                if ($InRightSwarm) {
                    Write-Verbose "In Correct Swarm"
                    #Test for manager count
                    if (($this.SwarmManagement -eq [SwarmManagement]::WorkerOnly) -or  ($LocalInfo.Swarm.managers -ge $this.ManagerCount )) {
                        Write-Verbose "Swarm State Good. Managers: $($LocalInfo.Swarm.managers)"
                        return $true    
                    }
                    else {
                        if ($LocalInfo.Swarm.ControlAvailable -eq $true) {
                            Write-Verbose "Not enough Managers: $($LocalInfo.Swarm.managers), but node is already a manager"
                            return $true
                        }
                        else
                        {
                        Write-Verbose "Not enough Managers: $($LocalInfo.Swarm.managers), need to be promoted"
                        return $false
                        }
                    }
                }
                else {
                    Write-Verbose "In Wrong Swarm: $($LocalInfo.Swarm.RemoteManagers.Addr) vs $($this.SwarmMasterURI)"
                    return $false
                }                
			}
			elseif ($LocalInfo.Swarm.LocalNodeState  -eq "inactive" -and ($this.SwarmMode -eq [Swarm]::Active)) {
                Write-Verbose "Swarm State $($LocalInfo.Swarm.LocalNodeState), should be $($this.SwarmMode)"				
                return $false
			}
			elseif ($LocalInfo.Swarm.LocalNodeState  -eq "active" -and ($this.SwarmMode -eq [Swarm]::Inactive)) {
                Write-Verbose "Swarm State $($LocalInfo.Swarm.LocalNodeState), should be $($this.SwarmMode)"				
				return $false
			}
			elseif ($LocalInfo.Swarm.LocalNodeState  -eq "inactive" -and ($this.SwarmMode -eq [Swarm]::Inactive)) {
                Write-Verbose "Swarm State Good"	
				return $true
			}
            else {
                Write-Verbose "Default return: failure to determine state"				
                return $false
            }
    }    
    # Gets the resource's current state.
    [cDockerSwarm] Get()
    {        
        $SwarmState = . "$($Env:ProgramFiles)\docker\docker.exe" info -f '{{ json .Swarm.LocalNodeState }}' | ConvertFrom-Json
			if ($SwarmState -eq "active"){
				$this.SwarmMode = [Swarm]::Active
			}
			elseif ($SwarmState -eq "inactive") {
				$this.SwarmMode = [Swarm]::Inactive
			}
        return $this 
    }
    
    [psobject]GetLocalDockerInfo(){
        #Try in a loop, in case docker was just restarted and is not ready yet
        $info = $null
        $i = 0
        while (!$info -and $i -lt 5) { 
            try{
                $i++
                $ErrorActionPreference = 'stop'
                Write-Verbose "Trying to get token from swarm manager"
                $info = . "$($Env:ProgramFiles)\docker\docker.exe" info -f '{{ json . }}' | ConvertFrom-Json                
                break
            }
            catch {
                Write-Verbose "Waiting for local docker to come online"
                start-sleep 5
            }            
        }
        return $info
    }

    [void]JoinSwarm($host, $tls,$type)
    {
        $token = $null
        $i = 0
        while (!$token -and $i -lt 5) { 
            try{
                $i++
                $ErrorActionPreference = 'stop'
                Write-Verbose "Trying to get token from swarm manager"
                $token = . "$($Env:ProgramFiles)\docker\docker.exe" -H $host $tls swarm join-token $type -q 
                break
            }
            catch {
                Write-Verbose "Waiting for manager to come online"
                start-sleep 15
            }
        
        }
        if ($token) {
            . "$($Env:ProgramFiles)\docker\docker.exe" swarm join --token $token $this.SwarmMasterURI
        }
        else {
            write-verbose "Failed to Get token; can't join swarm"
        }
    }    
}


# [DscResource()] indicates the class is a DSC resource.
[DscResource()]
class cDockerTLSAutoEnrollment
{

    # A DSC resource must define at least one key property.
    [DscProperty(Key)]
    [Ensure]$Ensure

    [DscProperty()]
    [String]$EnrollmentServer

    
    # Sets the desired state of the resource.
    [void] Set()
    {
        Write-Verbose "Using Enrollment Server: $($this.EnrollmentServer)"        
        $SwarmManagerIsMe = (Get-NetIPAddress).IPAddress -contains $this.EnrollmentServer
        Write-Verbose "Swarm Manager is this node: $SwarmManagerIsMe"
         if ($SwarmManagerIsMe -and $this.Ensure -eq [Ensure]::Present) {
            #Prepare for Enrollment
            if (!(Test-Path $env:SystemDrive\DockerTLSCA)) {
                Write-Verbose "Create Folder $("$env:SystemDrive\DockerTLSCA")"
                mkdir $env:SystemDrive\DockerTLSCA             
            }
            if (!(Test-Path $env:USERPROFILE\.docker)) {
                Write-Verbose "Create Folder $("$env:USERPROFILE\.docker")"
                mkdir $env:USERPROFILE\.docker
            }
            if (!(Test-Path $env:ALLUSERSPROFILE\docker\certs.d)) {
                Write-Verbose "Create Folder $("$env:ALLUSERSPROFILE\docker\certs.d")"
                mkdir $env:ALLUSERSPROFILE\docker\certs.d
            } 

            #Pull enrollment container 
            Write-Verbose "Getting Enrollment Container"
            . "$($Env:ProgramFiles)\docker\docker" pull pscripted/dsc-dockerswarm-tls:latest

            #Run TLS Enrollment Container
            #This will create local certs for the CA and running host, and allow other nodes to get their own signed certs from the CA            
            Write-Verbose "Running Enrollment Container"
            #Double convert to JSON for IPs to escape json to prevent docker clobbering
            . "$($Env:ProgramFiles)\docker\docker" run --restart unless-stopped -dit `
            -p 3000:3000 `
            -e DockerHost=$env:computername `
            -e DockerHostIPs=$((get-netipaddress -AddressFamily IPv4 -AddressState Preferred).IPaddress | convertto-json -Compress | convertto-json) `
            -v "$env:SystemDrive\DockerTLSCA:C:\DockerTLSCA" `
            -v "$env:ALLUSERSPROFILE\docker:$env:ALLUSERSPROFILE\docker" `
            -v "$env:USERPROFILE\.docker:c:\users\containeradministrator\.docker" pscripted/dsc-dockerswarm-tls:latest         
            
            $i = 0  
            while (!(Test-Path $env:ALLUSERSPROFILE\docker\certs.d\cert.pem) -and $i -lt 5) { 
                start-sleep 10
            }            
        }
        elseif ($this.Ensure -eq [ensure]::Present) {
            #Attempt enrollment from master            
            $i = 0  
            while (!(Test-Path $env:ALLUSERSPROFILE\docker\certs.d\cert.pem) -and $i -lt 10) { 
                try{
                    $i++
                    $ErrorActionPreference = 'stop'
                    Write-Verbose "Trying to enroll in TLS"
                    Install-cDSCSwarmTLSCert -SwarmMasterIP $this.EnrollmentServer -port 3000 -serverCerts
                    break
                }
                catch {
                    Write-Verbose "Waiting for TLS container to come online"
                    start-sleep 60
                }
            }
            if (Test-Path $env:ALLUSERSPROFILE\docker\certs.d\cert.pem) {
                write-verbose "Certificates Installed"
            }
            else {
                write-verbose "Failed to Get Certificates"
            }
        }
        elseif ($this.Ensure -eq [ensure]::Absent) {
            $containerID = . "$($Env:ProgramFiles)\docker\docker" ps -f "ancestor=pscripted/dsc-dockerswarm-tls:latest" -q     
            if ($containerID) {
                . "$($Env:ProgramFiles)\docker\docker" stop $containerID     
                . "$($Env:ProgramFiles)\docker\docker" rm $containerID
            }
        }
    }        
    
    # Tests if the resource is in the desired state.
    [bool] Test()
    {   
        Write-Verbose "Using Enrollment Server: $($this.EnrollmentServer)"        
        $SwarmManagerIsMe = (Get-NetIPAddress).IPAddress -contains $this.EnrollmentServer
        if ($SwarmManagerIsMe -and $this.Ensure -eq [Ensure]::Present) {
            if (. "$($Env:ProgramFiles)\docker\docker" ps -f "ancestor=pscripted/dsc-dockerswarm-tls:latest" -q) {
                Write-Verbose "Enrollment container already running"
                $running = $true
            }
            else {
                Write-Verbose "No Enrollment Container running"
                $running = $false
            }
                
            if ($this.Ensure -eq [Ensure]::Present) {
                return $running
            }
            else {
                return !$running
            }
        }
        else {
            Write-Verbose "Checking for Host Certificates"
            $CertExists = Test-Path $env:ALLUSERSPROFILE\docker\certs.d\cert.pem
            $KeyExists = Test-Path $env:ALLUSERSPROFILE\docker\certs.d\key.pem
            if ($CertExists -and $KeyExists) {
                return $true            
            }
            else{
                return $false
            }
        }
    }    
    # Gets the resource's current state.
    [cDockerTLSAutoEnrollment] Get()
    {   
        Write-Verbose "Using Enrollment Server: $($this.EnrollmentServer)"        
        $SwarmManagerIsMe = (Get-NetIPAddress).IPAddress -contains $this.EnrollmentServer
        if ($SwarmManagerIsMe -and $this.TLSOpenEnrollment) {     
            if (. "$($Env:ProgramFiles)\docker\docker" ps -f "ancestor=pscripted/dsc-dockerswarm-tls:latest" -q) {
                return $this.Ensure = [Ensure]::Present
            }
            else {
                return $this.Ensure = [Ensure]::Absent
            }
        }
        else {
            $CertExists = Test-Path $env:ALLUSERSPROFILE\docker\certs.d\cert.pem
            $KeyExists = Test-Path $env:ALLUSERSPROFILE\docker\certs.d\key.pem
            if ($CertExists -and $KeyExists) {
                 return $this.Ensure = [Ensure]::Present            
            }
            else{
                return $this.Ensure = [Ensure]::Absent
            }
        }
    }    
}

##Functions

##############################
#.SYNOPSIS
#Install Docker daemon certs provided by cDSCDockerSwarm enrollment container
#
#.DESCRIPTION
#Access the TLS AutoEnrollment Container for server and client certs for docker and download to appropriate directories
#
#.PARAMETER SwarmMasterIP
#IP of the host with the container running.
#
#.PARAMETER port
#Port the container is bound to. Default is 3000
#
#.EXAMPLE
#Install-cDSCSwarmTLSCert -SwarmMasterIP 192.168.0.20

##############################
function Install-cDSCSwarmTLSCert {
    [CmdletBinding()]
    param (
        [string]$SwarmMasterIP,
        [int]$port=3000,
        [switch]$serverCerts        
    )
    
    begin {
        if (!(Test-Path $env:ALLUSERSPROFILE\docker\certs.d)) {
            mkdir $env:ALLUSERSPROFILE\docker\certs.d | out-null
        }
        if (!(Test-Path $env:USERPROFILE\.docker)) {
            mkdir $env:USERPROFILE\.docker | out-null
        }
    }
    
    process {
        
        [array]$ips = (get-netipaddress -AddressState Preferred -AddressFamily IPv4).IPAddress
        if (($SwarmMasterIP -eq "localhost") -or ($ips -contains $SwarmMasterIP)) {
            $containerID = . "$($Env:ProgramFiles)\docker\docker" ps -f "ancestor=pscripted/dsc-dockerswarm-tls:latest" -q
            $containerIP = . "$($Env:ProgramFiles)\docker\docker" inspect $containerID -f '{{json .NetworkSettings.Networks.nat.IPAddress}}'
            $CAContainerURI = "$($containerIP | convertfrom-json):$port"
        }
        else {
            $CAContainerURI = "$($SwarmMasterIP):$port"
        }
        try {
            $Certs = Invoke-RestMethod "http://$CAContainerURI/swarmnode" -Method Post -Body (@{servername=$env:computername;ips=$ips} | Convertto-JSON) -ContentType "application/JSON" 
        }
        catch {
            Write-Error "Unable to connect to TLS Enrollment Server. AutoEnroll must be enabled in the DSC Configuration"
        }
        try {
                $certs.clientCert | out-file -FilePath  $env:USERPROFILE\.docker\cert.pem -Force -Encoding ascii
                $certs.clientKey  | out-file -FilePath  $env:USERPROFILE\.docker\key.pem -Force -Encoding ascii
                $certs.CACert | out-file -FilePath  $env:USERPROFILE\.docker\ca.pem -Force -Encoding ascii
            if ($PSBoundParameters.ContainsKey('serverCerts')) {
                $certs.ServerCert | out-file -FilePath  $env:ALLUSERSPROFILE\docker\certs.d\cert.pem -Force -Encoding ascii
                $certs.ServerKey | out-file -FilePath  $env:ALLUSERSPROFILE\docker\certs.d\key.pem -Force -Encoding ascii
                $certs.CACert | out-file -FilePath  $env:ALLUSERSPROFILE\docker\certs.d\ca.pem -Force -Encoding ascii
            }
        }
        catch {
            Write-Error "Unable to save all certificates"    
        }
    }
    
    end {
    }
}