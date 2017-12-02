<#
    Author:  Ricky Nelson
    Description:  SQL 2012 Database STIG
    Date:  13 April 2015
#>

Add-PSSnapin SqlServerCmdletSnapin100
Add-PSSnapin SqlServerProviderSnapin100

function insert-IntoChecklist {
     param (
        [string] $ServerName = "ServerName",
        [string] $Database = "Database",
        [string] $Stigid = "Stigid",
        [string] $Status = "Status",
        [string] $Category = "Category",
        [string] $CheckType = "CheckType",
        [string] $VulId = "VulId"
    )
    # create empty dataset object
    $dataset = New-Object System.Data.DataSet

    # query to see if record for today exists
    $dataset = Invoke-Sqlcmd -ServerInstance "SQL_Server_FQDN" -Database "SQL_stig" -Query "use stig; 
    select * from t_checklist 
    where 
    vulid = '$vulid'
    AND
    ServerName = '$servername'
    AND 
    DatabaseName = '$Database'
    ;"

    # If no record is returned for the previous query, create a new record; otherwise, update the existing record's Status value
    If($dataset -eq $null)
    {
    $query = "INSERT INTO t_Checklist(
                    stigid, status, Category, DatabaseName, ServerName, checktype, vulid) VALUES(
                    '$Stigid', '$Status', '$Category', '$Database', '$ServerName', '$CheckType', '$VulId');"
    }
    else{
        $query = "
        USE G6_stig
        UPDATE t_Checklist
        SET status = '$status'
        WHERE dateentered = convert(date, getdate())
        AND
        vulid = '$VulId'
        AND
        ServerName = '$servername'
        AND 
        DatabaseName = '$Database'
        AND
        DateEntered = getdate();"
     }
        
    
    # execute query
    Invoke-Sqlcmd -ServerInstance "SQL_Server_FQDN" -Database "SQL_stig" -Query $query
}

# Sample function
function SQL_00000 {
    param($server)
    # This is a template function
    insert-IntoChecklist -ServerName $server -Database "Master" -Stigid "SQL2-00-000100" -Status $status -Category "II" -CheckType "Database" -VulId "V-41311"
}

function SQL_15200 {
    param($server)
    Write-Host("Checking SQL2-00-015200 on $server`: SQL Server must be monitored to discover unauthorized changes to stored procedures.")


    # Create dataset to store the query data
    $dataset = New-Object System.Data.DataSet

    # Enter the SQL query results into the dataset
    $dataset = Invoke-Sqlcmd -ServerInstance $server -Query "EXEC msdb.dbo.sysmail_help_profile_sp;"

    # Get dbmail profile name
    $mailprofile =  $dataset.name

    # Create job via query
                                                                                                                                                                                                                                                                                                    
    $query =  "USE [msdb]
    GO

    /****** Object:  Job [Altered procedures check Vuln_Id  V-41403-6]    Script Date: 04/01/2015 10:22:28 ******/
    BEGIN TRANSACTION
    DECLARE @ReturnCode INT
    SELECT @ReturnCode = 0
    /****** Object:  JobCategory [[Uncategorized (Local)]]]    Script Date: 04/01/2015 10:22:28 ******/
    IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'[Uncategorized (Local)]' AND category_class=1)
    BEGIN
    EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

    END

    DECLARE @jobId BINARY(16)
    EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'Altered procedures check Vuln_Id  V-41403-6', 
		    @enabled=1, 
		    @notify_level_eventlog=0, 
		    @notify_level_email=0, 
		    @notify_level_netsend=0, 
		    @notify_level_page=0, 
		    @delete_level=0, 
		    @description=N'No description available.', 
		    @category_name=N'[Uncategorized (Local)]', 
		    @owner_login_name=N'sa', @job_id = @jobId OUTPUT
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
    /****** Object:  Step [execute query]    Script Date: 04/01/2015 10:22:28 ******/
    EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'execute query', 
		    @step_id=1, 
		    @cmdexec_success_code=0, 
		    @on_success_action=1, 
		    @on_success_step_id=0, 
		    @on_fail_action=2, 
		    @on_fail_step_id=0, 
		    @retry_attempts=0, 
		    @retry_interval=0, 
		    @os_run_priority=0, @subsystem=N'TSQL', 
		    @command=N'EXEC msdb.dbo.sp_send_dbmail
    @profile_name = ''$mailprofile'',
    @recipients = ''ricky.l.nelson8.civ@mail.mil'',
    @subject = ''Procedures and/or functions altered in the last 7 days'',
    @query = N''SELECT *
    FROM msdb..sysjobs
    WHERE
    datediff(day,date_modified,getdATE()) < 7;'',
    @attach_query_result_as_file = 1,
    @query_attachment_filename = ''altered_sysjobs.txt''', 
		    @database_name=N'master', 
		    @flags=0
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
    EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
    EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'Alter Monitor Job', 
		    @enabled=1, 
		    @freq_type=8, 
		    @freq_interval=1, 
		    @freq_subday_type=1, 
		    @freq_subday_interval=0, 
		    @freq_relative_interval=0, 
		    @freq_recurrence_factor=1, 
		    @active_start_date=20150331, 
		    @active_end_date=99991231, 
		    @active_start_time=0, 
		    @active_end_time=235959, 
		    @schedule_uid=N'6b8f99f1-1076-4fe2-8640-3797aa56123a'
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
    EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
    COMMIT TRANSACTION
    GOTO EndSave
    QuitWithRollback:
        IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
    EndSave:

    GO


    "


    # create job to monitor changes to system stored procedures, functions, and triggers
    try{     
        # Execute query
        Invoke-Sqlcmd  -ServerInstance $server -Query $query -ErrorAction Stop -ErrorVariable $qwer
    }

    # Error handling
    catch{
        $Error[0].Exception
    }

    Write-Host("Done") -ForegroundColor Green
}

function SQL_22000 {
    param($server)
    Write-Host("Checking SQL2-00-022000 on $server`:  SQL Server must protect against or limit the effects of the organization-defined types of Denial of Service (DoS) attacks.")

    # Get max concurrent connections query
    $query = "USE MASTER
    GO

    EXEC sys.sp_configure N'show advanced options', N'1'  RECONFIGURE WITH OVERRIDE
    GO
    EXEC sys.sp_configure N'user connections'
    EXEC sys.sp_configure N'show advanced options', N'0'  RECONFIGURE WITH OVERRIDE
    GO"

    # Execute query on server
    $sql = Invoke-Sqlcmd -ServerInstance $server -Query $query
    
    # Declare STIG status variable (non-declaration causing an issue with SQL i think)
    $status = $null

    # See if the max connection value is over the threshold
    if($sql.maximum -le 32767)
    {
        $status = "NotAFinding"
    }
    else{
        $status = "Open"
    }

    # Enter information into the database
    insert-IntoChecklist -ServerName $server -Database "Master" -Stigid "SQL2-00-022000" -Status $status -Category "II" -CheckType "Database" -VulId "V-41422"
    Write-Host("Done") -ForegroundColor Green
}

function SQL_23500 {
    param($server)
    Write-Host("Checking SQL2-00-023500 on $server`:  SQL Server job/batch queues must be reviewed regularly to detect unauthorized SQL Server job submissions.")
    # Query to determine if procedures are being executed automatically
    $query = `
    "SELECT *
    FROM master.sys.procedures
    WHERE is_auto_executed = 1"

    # Execute query
    $result = Invoke-Sqlcmd -ServerInstance $server -Database "master" -Query $query

    # If no procedures found, is not a finding
    if($result.Count -eq 0)
    {
        $status = "NotAFinding"
    }
    else{
        $status = "Open"
    }

    # Enter information into the database
    insert-IntoChecklist -ServerName $server -Database "Master" -Stigid "SQL2-00-023500" -Status $status -Category "II" -CheckType "Database" -VulId "V-41399"
    Write-Host("Done") -ForegroundColor Green
}

function SQL_24100 {
    param($server)

    # Check to see if/how many databases that are encrypted
    $query = "SELECT name
            FROM [master].sys.databases
            WHERE is_master_key_encrypted_by_server = 1
            AND owner_sid <> 1
            AND state = 0"

    # perform check
    $result = Invoke-Sqlcmd -ServerInstance "139.232.7.76" -Database "Master" -Query $query

    if($result.count -eq 0)
    {
        $status = "NotAFinding"
    }
    else
    {
        # If databases are returned SQL2-00-024100 should be consulted for further action requirements
        $status = "Open"
    }




}

function SQL_24200 {
    param($server)

    # query to find the number of cached/stored master keys
    $query = "SELECT COUNT(credential_id)
    FROM [master].sys.master_key_passwords"

    # execute query
    $result = Invoke-Sqlcmd -ServerInstance $server -Database "Master" -Query $query

    # check to ensure the result is 0
    if($result -eq 0)
    {
        $status = "NotAFinding"
    }
    else{
        $status = "Open"
    }

    # insert result into database
    insert-IntoChecklist -ServerName $server -Database "Master" -Stigid "SQL2-00-024200" -Status $status -Category "II" -CheckType "Database" -VulId "V-41416"

}

function SQL_011050 {
    param($server)

    # query for list of databases
    $dbQuery = "SELECT name FROM master.sys.databases;"

    # execute query to retrieve database list
    $dbList = Invoke-Sqlcmd -ServerInstance $server -Database "Master" -Query $dbQuery

    Foreach($db in $dbList)
    {
        $name = $db.name
        $query = "USE [$name] ;
            SELECT * 
            FROM sys.database_permissions
            WHERE state_desc = 'GRANT_WITH_GRANT_OPTION';" 
        
        
        $result = Invoke-Sqlcmd -ServerInstance $server -Database $name -Query $query

        if($result -eq $null)
        {
            $status = "NotAFinding"
        }
        else{
            $status = "Open"
        }
        
            
        insert-IntoChecklist -ServerName $server -Database $name -Stigid "SQL2-00-011050" -Status $status -Category "II" -CheckType "Database" -VulId "V-41394"
 
    }

    
}

function SQL_015600 {
    param($server)
    $query = "SELECT name AS 'Database name'
     , SUSER_SNAME(owner_sid) AS 'Database Owner'
     , state_desc AS 'Database state'
  FROM sys.databases"
    
    # execute query
    Invoke-Sqlcmd -ServerInstance $server -Database "Master" -Query $query | Out-File -FilePath "C:\temp\$server.Ownership.Authorization.csv"

    insert-IntoChecklist -ServerName $server -Database "Master" -Stigid "SQL2-00-015600" -Status "NotAFinding" -Category "II" -CheckType "Database" -VulId "V-41407"

}


<#
Rule Title:  SQL Server must encrypt information stored in the database.
STIG ID: SQL2-00-019300  Rule ID: SV-53939r1_rule  Vuln ID: V-41411
Severity: CAT II Class: Unclass
#>
function SQL_019300 {
    param($server)

    # query for list of databases
    $dbQuery = "SELECT name FROM master.sys.databases;"

    # execute query to retrieve database list
    $dbList = Invoke-Sqlcmd -ServerInstance $server -Database "Master" -Query $dbQuery

    #query to select all symmetric keys from each database
    

    foreach($db in $dblist)
    {
       $name = $db.name
       
       $query = "
       use [$name];
       select
        *
        from
        sys.symmetric_keys" 

        $result = Invoke-Sqlcmd -ServerInstance $server -Database $name -Query $query
        if($result -eq $null)
        {
            $status = "NotAFinding"
        }
        else{
            $status = "Open"
        }

        
        insert-IntoChecklist -ServerName $server -Database $name -Stigid "SQL2-00-019300" -Status $status -Category "II" -CheckType "Database" -VulId "V-41411"


    }
}

function SQL_021400 {
    param($server)
    
    # query to get a list of databases from the server
    $dbQuery = "SELECT name FROM master.sys.databases;"

    $dblist = Invoke-Sqlcmd -ServerInstance $server -Database "Master" -Query $dbQuery

    foreach($db in $dblist)
    {
        #get name of DB
        $name = $db.name

        # query to determine status of encryption per database
        $query = "USE [$name];
        IF NOT EXISTS
	        (
	        SELECT 1 
	        FROM sys.dm_database_encryption_keys
	        WHERE DB_NAME(database_id) = DB_NAME()
	        )
	        SELECT 
		        DB_NAME() AS [Database Name],
		        'No database encryption key present, no encryption' AS [Encryption State]
        ELSE
	        SELECT
		        DB_NAME(database_id)  AS [Database Name],
		        CASE encryption_state 
			        WHEN 0 THEN 'No database encryption key present, no encryption' 
			        WHEN 1 THEN 'Unencrypted' 
			        WHEN 2 THEN 'Encryption in progress' 
			        WHEN 3 THEN 'Encrypted' 
			        WHEN 4 THEN 'Key change in progress' 
			        WHEN 5 THEN 'Decryption in progress' 
			        WHEN 6 THEN 'Protection change in progress' 
		        END AS [Encryption State] 
	        FROM sys.dm_database_encryption_keys
	        WHERE DB_NAME(database_id) = DB_NAME()
        ;"

        # execute query
        $result = Invoke-Sqlcmd -ServerInstance $server -Database $name -Query $query
        
        # if encryption state = encrypted, not a finding
        if($result.'encryption state' -eq "Encrypted")
        {
            $status = "NotAFinding"
        }
        else{
            $status = "Open"
        }
        insert-IntoChecklist -ServerName $server -Database $name -Stigid "SQL2-00-021400" -Status $status -Category "II" -CheckType "Database" -VulId "V-41420"

    }
    
    
}

function SQL_022000 {
    param($server)
    
    # query to check for concurrent connections
    $query = "USE MASTER
    GO

    EXEC sys.sp_configure N'show advanced options', N'1'  RECONFIGURE WITH OVERRIDE
    GO
    EXEC sys.sp_configure N'user connections'
    EXEC sys.sp_configure N'show advanced options', N'0'  RECONFIGURE WITH OVERRIDE
    GO"

    # execute
    $result = Invoke-Sqlcmd -ServerInstance $server -Database "Master" -Query $query

    # Ensure max connections is not set to unlimited
    if($result.maximum -ne 0)
    {
        $status = "NotAFinding"
    }
    else{
        $status = "Open"
    }

    insert-IntoChecklist -ServerName $server -Database "Master" -Stigid "SQL2-00-022000" -Status $status -Category "II" -CheckType "Database" -VulId "V-41422"
}

function SQL_024000 {
    param($server)
    
    # query to get a list of databases from the server
    $dbQuery = "SELECT name FROM master.sys.databases;"

    $dblist = Invoke-Sqlcmd -ServerInstance $server -Database "Master" -Query $dbQuery

    foreach($db in $dblist)
    {
        #get name of DB
        $name = $db.name

        # query to determine status of encryption per database
        $query = "USE [$name]
        SELECT COUNT(name)
        FROM sys.symmetric_keys s, sys.key_encryptions k
        WHERE s.name = '##MS_DatabaseMasterKey##'
        AND s.symmetric_key_id = k.key_id
        AND k.crypt_type = 'ESKP';"

        # execute query
        $result = Invoke-Sqlcmd -ServerInstance $server -Database $name -Query $query
        
        # if encryption state = encrypted, not a finding
        if($result.Column1 -eq 0)
        {
            $status = "NotAFinding"
        }
        else{
            $status = "Open"
        }
       
        insert-IntoChecklist -ServerName $server -Database $name -Stigid "SQL2-00-024000" -Status $status -Category "II" -CheckType "Database" -VulId "V-41413"

    }
    
    
}
