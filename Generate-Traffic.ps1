# Define the target IP address of your VM
$vm_ip = "(enter VM IP)"

# Function to generate HTTP traffic (Port 80)
function Generate-HTTP-Traffic {
    try {
        Invoke-WebRequest -Uri "http://$vm_ip" -UseBasicParsing
    } catch {
        Write-Host "Failed to generate HTTP traffic: $_"
    }
}

# Function to generate HTTPS traffic (Port 443)
function Generate-HTTPS-Traffic {
    try {
        Invoke-WebRequest -Uri "https://$vm_ip" -UseBasicParsing
    } catch {
        Write-Host "Failed to generate HTTPS t# Define the target IP address of your VM
$vm_ip = "192.168.70.128"

# Function to generate HTTP traffic (Port 80)
function Generate-HTTP-Traffic {
    try {
        Invoke-WebRequest -Uri "http://$vm_ip" -UseBasicParsing
        Write-Host "Successfully generated HTTP traffic"
    } catch {
        Write-Host "Failed to generate HTTP traffic: $($_.Exception.Message)"
    }
}

# Function to generate HTTPS traffic (Port 443)
function Generate-HTTPS-Traffic {
    try {
        Invoke-WebRequest -Uri "https://$vm_ip" -UseBasicParsing
        Write-Host "Successfully generated HTTPS traffic"
    } catch {
        Write-Host "Failed to generate HTTPS traffic: $($_.Exception.Message)"
    }
}

# Function to generate SSH traffic (Port 22)
function Generate-SSH-Traffic {
    try {
        ssh user@$vm_ip "exit"
        Write-Host "Successfully generated SSH traffic"
    } catch {
        Write-Host "Failed to generate SSH traffic: $($_.Exception.Message)"
    }
}

# Function to generate DNS traffic (Port 53)
function Generate-DNS-Traffic {
    try {
        nslookup google.com $vm_ip
        Write-Host "Successfully generated DNS traffic"
    } catch {
        Write-Host "Failed to generate DNS traffic: $($_.Exception.Message)"
    }
}

# Function to generate ICMP traffic (Ping)
function Generate-ICMP-Traffic {
    try {
        Test-Connection -ComputerName $vm_ip -Count 4
        Write-Host "Successfully generated ICMP traffic"
    } catch {
        Write-Host "Failed to generate ICMP traffic: $($_.Exception.Message)"
    }
}

# Function to generate FTP traffic (Port 21)
function Generate-FTP-Traffic {
    try {
        $ftp = [System.Net.FtpWebRequest]::Create("ftp://$vm_ip/")
        $ftp.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $ftp.GetResponse()
        Write-Host "Successfully generated FTP traffic"
    } catch {
        Write-Host "Failed to generate FTP traffic: $($_.Exception.Message)"
    }
}

# Function to generate SMTP traffic (Port 25)
function Generate-SMTP-Traffic {
    try {
        $client = New-Object System.Net.Mail.SmtpClient($vm_ip, 25)
        $client.Send("from@example.com", "to@example.com", "Test Subject", "Test Body")
        Write-Host "Successfully generated SMTP traffic"
    } catch {
        Write-Host "Failed to generate SMTP traffic: $($_.Exception.Message)"
    }
}

# Function to generate RDP traffic (Port 3389)
function Generate-RDP-Traffic {
    try {
        mstsc /v:$vm_ip
        Write-Host "Successfully generated RDP traffic"
    } catch {
        Write-Host "Failed to generate RDP traffic: $($_.Exception.Message)"
    }
}

# Function to generate traffic for each protocol
function Generate-All-Traffic {
    Generate-HTTP-Traffic
    Generate-HTTPS-Traffic
    Generate-SSH-Traffic
    Generate-DNS-Traffic
    Generate-ICMP-Traffic
    Generate-FTP-Traffic
    Generate-SMTP-Traffic
    Generate-RDP-Traffic
}

# Generate traffic
Generate-All-Traffic
raffic: $_"
    }
}

# Function to generate SSH traffic (Port 22)
function Generate-SSH-Traffic {
    try {
        ssh user@$vm_ip "exit"
    } catch {
        Write-Host "Failed to generate SSH traffic: $_"
    }
}

# Function to generate DNS traffic (Port 53)
function Generate-DNS-Traffic {
    try {
        nslookup google.com $vm_ip
    } catch {
        Write-Host "Failed to generate DNS traffic: $_"
    }
}

# Function to generate ICMP traffic (Ping)
function Generate-ICMP-Traffic {
    try {
        Test-Connection -ComputerName $vm_ip -Count 4
    } catch {
        Write-Host "Failed to generate ICMP traffic: $_"
    }
}

# Function to generate FTP traffic (Port 21)
function Generate-FTP-Traffic {
    try {
        $ftp = [System.Net.FtpWebRequest]::Create("ftp://$vm_ip/")
        $ftp.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $ftp.GetResponse()
    } catch {
        Write-Host "Failed to generate FTP traffic: $_"
    }
}

# Function to generate SMTP traffic (Port 25)
function Generate-SMTP-Traffic {
    try {
        $client = New-Object System.Net.Mail.SmtpClient($vm_ip, 25)
        $client.Send("from@example.com", "to@example.com", "Test Subject", "Test Body")
    } catch {
        Write-Host "Failed to generate SMTP traffic: $_"
    }
}

# Function to generate RDP traffic (Port 3389)
function Generate-RDP-Traffic {
    try {
        mstsc /v:$vm_ip
    } catch {
        Write-Host "Failed to generate RDP traffic: $_"
    }
}


# Function to generate traffic for each protocol
function Generate-All-Traffic {
    Generate-HTTP-Traffic
    Generate-HTTPS-Traffic
    Generate-SSH-Traffic
    Generate-DNS-Traffic
    Generate-ICMP-Traffic
    Generate-FTP-Traffic
    Generate-SMTP-Traffic
    Generate-RDP-Traffic
}

# Generate traffic
Generate-All-Traffic
