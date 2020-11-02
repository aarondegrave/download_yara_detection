# download_yara_detection
Constantly looks at the windows downloads folder for updates, if something is added your yara ruleset is run against that file/folder. If a match occurs, permissions of the file are changed, attributes of the file are changed and the file extension is changed so execution is not possible. 

# Usage
This could be setup to run on startup in hidden mode, the program gets the user account that is running and scans that users download folder every second for updates. Make sure to change the rule_location variable within the code, to the location your yara rules are.
