# download_yara_detection
Constantly looks at the windows downloads folder for updates, if something is added your yara ruleset is run against that file/folder. If a match occurs, permissions of the file are changed, attributes of the file are changed and the file extension is changed so execution is not possible. 
