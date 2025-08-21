#Reads the users.csv file
$users = Import-Csv -Path "C:\Users\KIIT\Projects\AutomatingUserAccount\user.csv"

$logFile = "C:\Users\KIIT\Projects\AutomatingUserAccount\user_management_log.csv"

#Function to log action:

function Log-Action {
    param (
        [string]$message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logmessage = "$timestamp - $message"
    Add-Content -Path $logFile -Value $logmessage
}

#Reiterate through each user present in file
foreach ($user in $users) {
    $username = $user.Username
    $password = $user.Password
    $role = $user.Role

    $existingUser = Get-LocalUser -Name $username -ErrorAction SilentlyContinue

    if($existingUser){
        Log-Action "User '$username' exists, updating the account"

        Set-LocalUser -Name $username -Password (ConvertTo-SecureString -AsPlainText $password -Force)

        #check if the particular user is part or not 
        $groupMembers = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name

        if ($role -eq "Administrator") {
            if ($groupMembers -notcontains $username) {
                Add-LocalGroupMember -Group "Administrators" -Member $username
                Log-Action "The user named '$username' is added to the Administrators group."
            } else {
                Log-Action "'$username' is already a member of the 'Administrators' group."
            }
        } elseif ($role -eq "Standard User"){
            if ($groupMembers -contains $username) {
                Remove-LocalGroupMember -Group "Administrators" -Member $username
                Log-Action "Removed '$username' from the Administrators group."
            } else {
                Log-Action "'$username' is not a member of the 'Administrators' group."
            }
        }
    } else {
        Log-Action "Creating new user '$username'."

        #Creating new user
        New-LocalUser -Name $username -Password (ConvertTo-SecureString -AsPlainText $password -Force) -FullName $username -Description "Created the new user in your system."
        Log-Action "User '$username' created successfully."

        #Assigning the roles now.
        if ($role -eq "Administrator") {
            Add-LocalGroupMember -Group "Administrators" -Member $username
            Log-Action "Added '$username' to the 'Administrators' group."
        } elseif ($role -eq "Standard User") {
            Add-LocalGroupMember -Group "Users" -Member $username
            Log-Action "Added '$username' to the 'Users' group."
        }
    }

   # ...existing code...
    #Create home directory for the users and set the permissions.
    $homeDir = "C:\Users\$username"
    if (-not (Test-Path -Path $homeDir)) {
        try {
            New-Item -Path $homeDir -ItemType Directory -Force
            Log-Action "Created home directory for '$username' at '$homeDir'."
        } catch {
            Log-Action "Failed to create home directory for '$username': $_"
            continue
        }
    } else {
        Log-Action "Home directory for '$username' already exists at '$homeDir'."
    }

    #setting up the permissions.
    try {
        $acl = Get-Acl -Path $homeDir
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, "FullControl", "Allow")
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $homeDir -AclObject $acl
        Log-Action "Set full control permission for '$username' on their home directory"
    } catch {
        Log-Action "Failed to set permissions for '$username' on '$homeDir': $_"
    }
}