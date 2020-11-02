import os 
import time
import getpass
import yara
from stat import S_IREAD, S_IRGRP, S_IROTH
import subprocess

username = getpass.getuser()
watch = "C:\\Users\\" + username + "\\Downloads\\"
rule_location = "C:\\yara_rules\\"
beforecheck = dict ([(f, None) for f in os.listdir (watch)])
while 1:
  time.sleep (1)
  aftercheck = dict ([(f, None) for f in os.listdir (watch)])
  added = [f for f in aftercheck if not f in beforecheck]
  removed = [f for f in beforecheck if not f in aftercheck]
  if added: print ("Added: ", ", ".join (added))
  if removed: print ("Removed: ", ", ".join (removed))
  out_string = " "
  listtostring= out_string.join(added)
  if os.path.isfile(watch + listtostring):
    rules = os.listdir(rule_location)
    for rule in rules:
        yara_rule = os.path.join(rule_location + rule)
        if yara_rule.endswith('.yar') or yara_rule.endswith(".yara"):
            compiledrules = yara.compile(filepath=yara_rule)
            try:
                matches = compiledrules.match(watch + listtostring)
                if matches:
                    print(listtostring, matches)
                    os.chmod(listtostring, S_IREAD|S_IRGRP|S_IROTH)
                    subprocess.check_call(['attrib', '+H', listtostring])
                    base = os.path.splitext(listtostring)[0]
                    os.rename(listtostring, base + ".psq")
            except yara.Error as e:
                continue
        else:
            continue
  else:
    for root,dirs,files in os.walk(watch+listtostring, topdown=False):
        if added:
            for name in files:
                rules = os.listdir(rule_location)
                for rule in rules:
                    yara_rule = os.path.join(rule_location + rule)
                    if yara_rule.endswith(".yar") or yara_rule.endswith(".yara"):
                        compiledrules = yara.compile(filepath=yara_rule)
                        try:
                            matches=compiledrules.match(watch + listtostring + "\\" +  name)
                            if matches:
                                print(name,matches)
                                os.chmod(listtostring, S_IREAD|S_IRGRP|S_IROTH)
                                subprocess.check_call(['attrib', '+H', listtostring])
                                base = os.path.splitext(listtostring)[0]
                                os.rename(listtostring, base + ".psq")
                        except yara.Error as e:
                            continue
  beforecheck = aftercheck
