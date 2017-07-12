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

    [DscProperty(Key)]
    [Ensure]$Ensure

    [DscProperty()]
    [string]$version

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
                Write-Verbose "Registerin Docker Service"
                dockerd.exe --register-service
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

    # A DSC resource must define at least one key property.
    [DscProperty(Key)]
    [string]$registryURI

    [DscProperty(Mandatory)]
    [string]$Certificate

    # Mandatory indicates the property is required and DSC will guarantee it is set.
    [DscProperty(Mandatory)]
    [Ensure] $ensure

    # NotConfigurable properties return additional information about the state of the resource.
    # For example, a Get() method might return the date a resource was last modified.
    # NOTE: These properties are only used by the Get() method and cannot be set in configuration.        

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
                $currentCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $currentCert.Import("$CertPath\ca.crt")
                                    
                                    
                $enc = [system.Text.Encoding]::UTF8
                $desiredCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $desiredCert.Import($enc.GetBytes($this.Certificate))

                                   
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
            if(test-path "C:\ProgramData\docker\certs.d\$($this.registryURI -replace ':','')\ca.crt") {
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
        if(test-path "C:\ProgramData\docker\certs.d\$($this.registryURI -replace ':','')\ca.crt") {
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

    # A DSC resource must define at least one key property.
    [DscProperty(Key)]
    [Ensure]$Ensure

    [DscProperty()]
    [string]$BaseConfigJson='{}'

    [DscProperty()]
    [string[]] $InsecureRegistries

    [DscProperty()]
    [string[]] $Labels

    [DscProperty()]
    [string]$DaemonBinding='tcp://0.0.0.0:2375'

    [DscProperty()]
    [boolean] $ExposeAPI
    
    [DscProperty()]
    [boolean] $RestartOnChange

    # Sets the desired state of the resource.
    [void] Set()
    {    
        if ($this.Ensure -eq [Ensure]::Present) {
              
            $pendingConfiguration = $this.GetPendingConfiguration()
           
            #Write Configuration
            $pendingConfiguration |  Out-File "$($env:ProgramData)\docker\config\daemon.json" -Encoding ascii -Force
            #Restart docker service if the configuration changed
            if ($this.RestartOnChange) {
                Restart-Service Docker
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
            if(Test-Path "$($env:ProgramData)\docker\config\daemon.json"){            
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
            if(Test-Path "$($env:ProgramData)\docker\config\daemon.json"){
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
        $ConfigExists = Test-Path "$($env:ProgramData)\docker\config\daemon.json"    
        if($ConfigExists){            
            $currentConfiguration = ((Get-Content "$($env:ProgramData)\docker\config\daemon.json") | Out-String | ConvertFrom-Json)    
            $this.Ensure = [ensure]::Present
        }
        else {
            $this.Ensure = [ensure]::Absent
        }
        return $this
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

    # A DSC resource must define at least one key property.
    [DscProperty(Key)]
    [string]$SwarmMasterURI

    # Mandatory indicates the property is required and DSC will guarantee it is set.
    [DscProperty(Mandatory)]
    [Swarm] $SwarmMode

    [DscProperty()]
    [int] $ManagerCount=3

    [DscProperty(Mandatory)]
    [SwarmManagement]$SwarmManagement


    
    # Sets the desired state of the resource.
    [void] Set()
    {    
        $SwarmDockerHost = $this.swarmURI.Split(':')[0]

        $SwarmInfo = docker -H $SwarmDockerHost info -f '{{ json .Swarm }}' | ConvertFrom-Json
        $managers = $SwarmInfo.managers

        $LocalInfo = docker info -f '{{ json . }}' | ConvertFrom-Json
        if ($LocalInfo.Swarm.LocalNodeState -eq "active") {
            $InRightSwarm = $LocalInfo.Swarm.RemoteManagers.Addr -contains $this.SwarmMasterURI
            if (!$InRightSwarm) {
                Write-Verbose "Server is in the wrong swarm; leaving"
                docker swarm leave -f
            }
            elseif ($this.SwarmMode -eq [Swarm]::Inactive) {
                Write-Verbose "Server is in the a swarm and should be inactive; leaving"
			    docker swarm leave -f
		    }
            elseif (($this.SwarmMode -eq [Swarm]::Active) -and ($managers -lt $this.ManagerCount)) {
                docker -H $SwarmDockerHost node promote $env:COMPUTERNAME
            }
        }
        elseif ($this.SwarmMode -eq [Swarm]::Active) {
			$managers = docker -H  $SwarmDockerHost info -f '{{ json .Swarm.Managers }}'
            if (($this.SwarmManagement -eq [SwarmManagement]::Automatic) -and ($managers -lt $this.ManagerCount)) {
                $token = docker -H $SwarmDockerHost swarm join-token manager -q
                docker swarm join --token $token $this.SwarmMasterURI
            }
            else {
                $token = docker -H $SwarmDockerHost swarm join-token worker -q
                docker swarm join --token $token $this.SwarmMasterURI
            }
		}
		
    }        
    
    # Tests if the resource is in the desired state.
    [bool] Test()
    {        

            
            $LocalInfo = docker info -f '{{ json . }}' | ConvertFrom-Json
            
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
        $SwarmState = docker info -f '{{ json .Swarm.LocalNodeState }}' | ConvertFrom-Json
			if ($SwarmState -eq "active"){
				$this.SwarmMode = [Swarm]::Active
			}
			elseif ($SwarmState -eq "inactive") {
				$this.SwarmMode = [Swarm]::Inctive
			}
        return $this 
    }    
}