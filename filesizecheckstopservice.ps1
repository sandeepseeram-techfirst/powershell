 $File = 'C:\Users\sande\Desktop\Article Pics\Test.txt'

IF (Test-Path $File) {
    If ((Get-Item $File).length -gt 5kb) {
      Write-Output [$(Get-Date)]:" FILE IS OK FOR PROCESSING! "
      Stop-Service -Name "SNMPTRAP"
      Start-Sleep -s 60
      # Get the date
      $DateStamp = get-date -uformat "%Y-%m-%d@%H-%M-%S"
      rename-item "$File" "$(Archieve-$DateStamp)"
      Start-Sleep -s 60
      Start-Service -Name "SNMPTRAP"
    }
Else {
     Exit
}
}