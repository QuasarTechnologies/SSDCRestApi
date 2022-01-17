#Script to run Postman tests
#Anasoft Inc.(s) 2020
#07 Nov 2020
#Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

[system.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null   



function Send-Email {            
[cmdletbinding()]            
param( 
 [string]$SmtpServer,                       
 [string]$EmailsTo,   
 [string]$From,                       
 [string]$ReplayTo,
 [string]$Subject,  
 [string]$Body,
 [string]$Attachment,
 [string]$PassedAllTests       
)            

     #Creating a Mail object
     $msg = new-object Net.Mail.MailMessage
     #Creating SMTP server object
     $smtp = new-object Net.Mail.SmtpClient($SmtpServer)
     #Email structure 
     $msg.From = $From
     $msg.ReplyTo = $ReplayTo
     #send to
     $EmailsToList = $EmailsTo.split(",");
     foreach($l in $EmailsToList){
       $msg.To.Add($l) 
      }
     $msg.subject = $Subject
     if($PassedAllTests -eq 0)
        {$msg.Priority = [System.Net.Mail.MailPriority]::High}
     $attach = new-object Net.Mail.Attachment($Attachment) 
     if ($attach -ne $null)
        {$msg.Attachments.Add($attach)}
     $msg.IsBodyHtml = $true
     $msg.body = $Body     
     #Sending email 
     $smtp.Send($msg)
         
}


#read config file
#$ScriptRoot = Get-Variable -Name PSScriptRoot -ValueOnly -ErrorAction Stop
$ScriptRoot = $PSScriptRoot
Write-Host $ScriptRoot
$configFilePath = $ScriptRoot + "\config.txt"

$config = get-content $configFilePath
$testsCollectionFilePath = $ScriptRoot + "\" + $config[0]
$testsReporterSummaryExportFilePath = $ScriptRoot + "\" + $config[1]
$testsReporterSummaryTemplateFilePath = $ScriptRoot + "\" + $config[2]
$testsReporterDetailedExportFilePath = $ScriptRoot + "\" + $config[3]
$testsCollectionFolder = $config[4]
$testsIterationsCount = $config[5]
$MessageFail = $config[6]
$MessagePass = $config[7]
$OpenReport =  $config[8]
$SendEmail =  $config[9]
$smtpServer = $config[10]
$Emails =  $config[11]
$ServiceName =  $config[12]

$nl = [Environment]::NewLine

##################
Write-Host $nl "--------------------------------------------------------"
Write-Host "Running Postman tests - " + $ServiceName
$currentdate=(Get-Date).ToString("yyyy/M/d H:m:s")
Write-Host $currentdate

#Get-Content $logFilePath

#summary html report
Write-Host "Running Postman tests - summary"
newman run $testsCollectionFilePath --folder $testsCollectionFolder -r html --reporter-html-template $testsReporterSummaryTemplateFilePath --reporter-html-export $testsReporterSummaryExportFilePath

#full html report 
Write-Host "Running Postman tests - detailed"
newman run $testsCollectionFilePath --folder $testsCollectionFolder -r htmlextra -n $testsIterationsCount --reporter-htmlextra-export $testsReporterDetailedExportFilePath --reporter-htmlextra-title "$ServiceName Postman tests"

$pass = @(Get-Content $testsReporterSummaryTemplateFilePath | Where-Object { $_.Contains("failures0") } ).Count -eq 1
$report = get-content $testsReporterSummaryTemplateFilePath -Raw

if ($pass)
 {
   $subject = $MessagePass
   $passedAllTests = 1
 }
Else
 {
   $subject = $MessageFail
   $passedAllTests = 0
 }

#run created test report
if ($OpenReport -eq $True)
{
    Invoke-Item $testsReporterSummaryExportFilePath
}

#send email(s) with attached  \detailed report every time if any receiver
if($SendEmail -eq $True)
{
    if ($Emails)
    {
	    Send-Email -SmtpServer $smtpServer -EmailsTo $Emails -From "no-reply@no-reply.com" -ReplayTo "no-reply@no-reply.com" -Subject $subject -Body $report  -Attachment $testsReporterFileExportPath -PassedAllTests $passedAllTests
        Write-Host "Email sent."
    }
    Else
    {
        Write-Host "Email not sent. No receiver found."
    }
}


Write-Host "Done."