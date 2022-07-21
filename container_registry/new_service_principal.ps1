 
$registryName = '<container-registry-name>'
$resourceGroup = '<resource-group-name>'
$servicePrincipalName = 'acr-service-principal'

 
$registry = Get-AzContainerRegistry -ResourceGroupName $resourceGroup -Name $registryName

# Create the service principal
$sp = New-AzADServicePrincipal -DisplayName $servicePrincipalName
 
Start-Sleep -Seconds 30

 
New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName acrpull -Scope $registry.Id
 
Write-Output "Service principal App ID: $($sp.AppId)"
Write-Output "Service principal password: $($sp.PasswordCredentials.SecretText)"
