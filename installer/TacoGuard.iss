; TacoGuard's Setup (Inno Setup 6). Built by tools/build_installer.py, which stages the files and runs
;   ISCC /DAppVersion=<x.y.z> /DStage=<build\installer\stage> /DOutDir=<dist> installer\TacoGuard.iss
;
; Per user, no admin rights: everything goes into %LOCALAPPDATA%\Programs\TacoGuard (the same folder
; `python -m tacoguard install` uses, so self-update, start at sign-in and the launcher work unchanged).
;   runtime\   python.org's own Python (its full Windows package, checksum checked at build time)
;   setup\     TacoGuard's files and its pinned parts; tools\install_step.py turns them into venv\ +
;              versions\<version>\ and is deleted afterwards
; Uninstall runs `TacoGuard.pyw uninstall --keep-files` first (start-at-sign-in entry, decoy files,
; the hosts block), then deletes the folder. The data folder (settings, quarantine) is kept.

#ifndef AppVersion
  #error Run tools\build_installer.py (it passes AppVersion and Stage)
#endif
#ifndef OutDir
  #define OutDir "..\dist"
#endif

[Setup]
AppId={{D2B848E6-E9C6-4B97-80B0-C817204CC46D}
AppName=TacoGuard
AppVersion={#AppVersion}
AppVerName=TacoGuard {#AppVersion}
AppPublisher=TacoGuard (open source)
AppPublisherURL=https://github.com/mAgNiFiCeNtTaCo/TacoGuard
AppSupportURL=https://github.com/mAgNiFiCeNtTaCo/TacoGuard/issues
AppComments=A second-opinion malware scanner that works next to Microsoft Defender.
DefaultDirName={localappdata}\Programs\TacoGuard
DisableDirPage=yes
UsePreviousAppDir=no
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 11 (the only Windows TacoGuard is tested on)
MinVersion=10.0.22000
LicenseFile={#Stage}\LICENSE.txt
OutputDir={#OutDir}
OutputBaseFilename=TacoGuard-Setup-{#AppVersion}
SetupIconFile={#Stage}\TacoGuard.ico
UninstallDisplayIcon={app}\TacoGuard.ico
UninstallDisplayName=TacoGuard
Compression=lzma2/ultra64
SolidCompression=yes
LZMANumBlockThreads=4
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Tasks]
Name: "startmenu"; Description: "Add TacoGuard to the Start menu"
Name: "desktopicon"; Description: "Add a desktop shortcut"; Flags: unchecked
Name: "signin"; Description: "Start TacoGuard when I sign in to Windows (you can change this in Settings)"

[Files]
Source: "{#Stage}\.tacoguard-install.json"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "{#Stage}\TacoGuard.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#Stage}\setup\*"; DestDir: "{app}\setup"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\TacoGuard"; Filename: "{app}\venv\Scripts\pythonw.exe"; Parameters: """{app}\TacoGuard.pyw"""; WorkingDir: "{app}"; IconFilename: "{app}\TacoGuard.ico"; Comment: "TacoGuard: a second-opinion malware scanner"; Tasks: startmenu
Name: "{userdesktop}\TacoGuard"; Filename: "{app}\venv\Scripts\pythonw.exe"; Parameters: """{app}\TacoGuard.pyw"""; WorkingDir: "{app}"; IconFilename: "{app}\TacoGuard.ico"; Comment: "TacoGuard: a second-opinion malware scanner"; Tasks: desktopicon

[Run]
Filename: "{app}\venv\Scripts\pythonw.exe"; Parameters: """{app}\TacoGuard.pyw"""; WorkingDir: "{app}"; Description: "Open TacoGuard now"; Flags: postinstall nowait skipifsilent; Check: InstallStepOK

[UninstallDelete]
; what TacoGuard's install step and self-update made (Setup removes its own files itself)
Type: filesandordirs; Name: "{app}\venv"
Type: filesandordirs; Name: "{app}\versions"
Type: filesandordirs; Name: "{app}\setup"
; Python writes __pycache__ folders into runtime\ when it first runs; Setup doesn't know those files
Type: filesandordirs; Name: "{app}\runtime"
Type: files; Name: "{app}\current.json"
Type: files; Name: "{app}\health.json"
Type: files; Name: "{app}\requirements.lock"
Type: files; Name: "{app}\requirements.lock.new"
Type: files; Name: "{app}\TacoGuard.pyw"
Type: files; Name: "{app}\TacoGuard.cmd"
Type: files; Name: "{app}\update.lock"
Type: files; Name: "{app}\update_result.json"
Type: files; Name: "{app}\update_state.json"
Type: files; Name: "{app}\setup-log.txt"
Type: files; Name: "{app}\*.tmp"
Type: files; Name: "{app}\.tacoguard-install.json"
Type: dirifempty; Name: "{app}"

[Code]
var
  StepFailed: Boolean;

function InstallStepOK(): Boolean;
begin
  Result := not StepFailed;
end;

function LogTail(): String;
var
  S: AnsiString;
begin
  Result := '';
  if LoadStringFromFile(ExpandConstant('{app}\setup-log.txt'), S) then
  begin
    if Length(S) > 1500 then
      S := Copy(S, Length(S) - 1500, 1501);
    Result := String(S);
  end;
end;

procedure RunInstallStep();
var
  Params: String;
  Data: String;
  Code: Integer;
begin
  Params := '-I "' + ExpandConstant('{app}\setup\install_step.py') + '" --root "' + ExpandConstant('{app}') + '"';
  Data := ExpandConstant('{param:data|}');
  if Data <> '' then
    Params := Params + ' --data "' + Data + '"';
  if not WizardIsTaskSelected('signin') then
    Params := Params + ' --no-sign-in';
  WizardForm.StatusLabel.Caption := 'Setting up TacoGuard''s own Python and checking it works (about a minute)...';
  WizardForm.ProgressGauge.Style := npbstMarquee;
  try
    if not Exec(ExpandConstant('{app}\runtime\python.exe'), Params, ExpandConstant('{app}'), SW_HIDE,
                ewWaitUntilTerminated, Code) then
      Code := -1;
  finally
    WizardForm.ProgressGauge.Style := npbstNormal;
  end;
  if Code = 0 then
    DelTree(ExpandConstant('{app}\setup'), True, True, True)
  else
  begin
    StepFailed := True;
    SuppressibleMsgBox('TacoGuard could not finish setting up (code ' + IntToStr(Code) + '). ' +
      'If TacoGuard is already running, quit it (tray icon, Quit) and run Setup again.' + #13#10#13#10 +
      LogTail(), mbError, MB_OK, IDOK);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    RunInstallStep();
end;

function GetCustomSetupExitCode(): Integer;
begin
  if StepFailed then
    Result := 20
  else
    Result := 0;
end;

function InitializeUninstall(): Boolean;
var
  Python, Launcher: String;
  Code: Integer;
begin
  Result := True;
  Python := ExpandConstant('{app}\venv\Scripts\python.exe');
  Launcher := ExpandConstant('{app}\TacoGuard.pyw');
  if not (FileExists(Python) and FileExists(Launcher)) then
    Exit;
  if Exec(Python, '"' + Launcher + '" uninstall --root "' + ExpandConstant('{app}') + '" --keep-files',
          ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 3) then
  begin
    SuppressibleMsgBox('TacoGuard is still running. Quit it first (right-click the tray icon, Quit), ' +
      'then uninstall again.', mbError, MB_OK, IDOK);
    Result := False;
  end;
end;
