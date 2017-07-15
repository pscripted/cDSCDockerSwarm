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

            if (!((Get-PackageProvider -ListAvailable).Name -contains "DockerMsftProvider")) {
                Write-Verbose "Install DockerMsftProvider Provider"
                Install-Module -Name DockerMsftProvider -Repository psgallery -Force
            }    
             
            $package = Find-Package -ProviderName DockerMsftProvider -RequiredVersion $GetVersion

            if ($package) {
                Write-Verbose "Required version package was found in provider. Installing"
                Install-Package $package -Update
            }
            else {
                Write-Verbose "Package was not found in provider"
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
            Write-Verbose "Starting Docker Service"
            Start-Service docker  
        }
    }        
    
    # Tests if the resource is in the desired state.
    [bool] Test()
    {
        if ($this.DownloadChannel -eq "EE") {
            if ((Get-PackageProvider).Name -contains "DockerMsftProvider") {
                $dockerPackage = Find-Package -ProviderName DockerMsftProvider
                if ($dockerPackage)   {
                    if ($dockerPackage.Version -eq $this.version) {
                        return $true
                    }
                    else {
                        Write-Verbose "Incorrect docker version installed"
                        return $false
                    }
                }
                else {
                    Write-Verbose "Docker is not installed"
                    return $false
                }
            }
            else {
                Write-Verbose "DockerMsftProvider Package Provider is missing"
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
    [string]$DaemonBinding='tcp://0.0.0.0:2375'

    #Adds named pipe and TCP bindings to configuration, allowing external access. This is required for Swarm mode
    [DscProperty()]
    [boolean] $ExposeAPI
    
    #Restart docker on any chane of the configuration
    [DscProperty()]
    [boolean] $RestartOnChange

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
        if($this.exposeApi -eq $true){
			$pendingConfiguration | Add-Member -Name "hosts" -MemberType NoteProperty -Value @($this.daemonBinding, "npipe://")
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
        $SwarmInfo = . "$($Env:ProgramFiles)\docker\docker.exe" -H $SwarmDockerHost info -f '{{ json .Swarm }}' | ConvertFrom-Json
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
                . "$($Env:ProgramFiles)\docker\docker.exe" -H $SwarmDockerHost node promote $env:COMPUTERNAME
            }
        }
        elseif ($this.SwarmMode -eq [Swarm]::Active) {
            #$managers = docker -H  $SwarmDockerHost info -f '{{ json .Swarm.Managers }}'
            if ($SwarmManagerIsMe) {
                Write-Verbose "Creating a new Swarm"
                . "$($Env:ProgramFiles)\docker\docker.exe" swarm init --advertise-addr $this.SwarmMasterURI
            }
            elseif (($this.SwarmManagement -eq [SwarmManagement]::Automatic) -and ($managers -lt $this.ManagerCount)) {
                Write-Verbose "Joining the Swarm as a manager"
                $this.JoinSwarm($SwarmDockerHost, "manager")
            }
            else {
                Write-Verbose "Joining the Swarm as a worker"
                $this.JoinSwarm($SwarmDockerHost, "worker")
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
    
    [string]GetLocalDockerInfo(){
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

    [void]JoinSwarm($host,$type)
    {
        $token = $null
        $i = 0
        while (!$token -and $i -lt 5) { 
            try{
                $i++
                $ErrorActionPreference = 'stop'
                Write-Verbose "Trying to get token from swarm manager"
                $token = . "$($Env:ProgramFiles)\docker\docker.exe" -H $host swarm join-token $type -q 
                break
            }
            catch {
                Write-Verbose "Waiting for manager to come online"
                start-sleep 5
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