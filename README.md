# Azure-Sentinal-Mimecast
Instructions to deploy into Azure Function and testing to be completed soon. For now use Prime and Pump.ps1 to get 1st MS-SIEM-Token and place in Azure Functions app configuration pair key:value >> mcsiemtoken

Once token has been entered create a Azure Function PS, create a Timmer Trigger for every 30 minutes and place code from SIEMLogs.ps1 in function. Fill out the variables. Function will run every 30 minutes to get the latest logs and get new MC-SIEM-Token to pick up where last left off and post data to Log Analytics.

assets for Azure Sentinel using Mimecast SIEM and TTP logs as source. Includes .ps1 Azure functions for obtaining logs using Mimecast APIs.
