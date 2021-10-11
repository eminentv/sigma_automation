#!/bin/bash
RULES=rules/
APPLICATIONS=rules/application
AWS=rules/cloud/aws
AZURE=rules/cloud/azure
GCP=rules/cloud/gcp
o365=rules/cloud/m365
COMPLIANCE=rules/generic
GENERIC=rules/generic
LINUX=rules/linux
LINUX_AUDITD=rules/linux/auditd
LINUX_MODSEC=rules/linux/modsecurity
NETWORK=rules/network
CISCO=rules/network/cisco
ZEEK=rules/network/zeek
PROXY=rules/proxy
WEB=rules/web
WINDOWS=rules/windows

mkdir txt-rules

ls ${RULES} >> rules_dir.txt
while read -r line;
do
    mkdir -p update/$line;
done < rules_dir.txt \

# Application rules
title=application
mkdir -p update/$title/filebeat

ls ${APPLICATIONS} >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${APPLICATIONS}/$line > update/$title/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/filebeat/$line;
done < txt-rules/$title-rules.txt


# Cloud AWS
title=cloud
title2=aws
mkdir update/$title/$title2
ls ${AWS} >> txt-rules/$title2-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-cloudtrail ${AWS}/$line > update/$title/$title2/$line;
  echo "import: BaseHive.config" >> update/$title/$title2/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/$line;
done < txt-rules/$title2-rules.txt

# Cloud Azure
title=cloud
title2=azure
mkdir update/$title/$title2
mkdir update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${AZURE} >> txt-rules/$title2-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${AZURE}/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${AZURE}/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title2-rules.txt

# GCP
title=cloud
title2=gcp
mkdir update/$title/$title2
mkdir update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${GCP} >> txt-rules/$title2-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${GCP}/$line > update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line;
done < txt-rules/$title2-rules.txt

# O365
title=cloud
title2=o365
mkdir update/$title/$title2
mkdir update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${o365} >> txt-rules/$title2-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${o365}/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${o365}/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title2-rules.txt

# Compliance
title=compliance
mkdir -p update/$title/filebeat
mkdir update/$title/winlogbeat
ls ${COMPLIANCE}} >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${title}/$line > update/$title/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${title}/$line > update/$title/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Generic
title=generic
mkdir -p update/$title/filebeat
mkdir update/$title/winlogbeat
ls ${GENERIC} >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${GENERIC}/$line > update/$title/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${GENERIC}/$line > update/$title/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Linux
title=linux
mkdir -p update/$title/filebeat
ls ${LINUX} >> txt-rules/$title-rules.txt
sed -e 's/auditd//g' txt-rules/$title-rules.txt
sed -e 's/modsecurity//g' txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${LINUX}/$line > update/$title/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/filebeat/$line;
done < txt-rules/$title-rules.txt

# Linux Audit
title=linux-aud
mkdir -p update/$title/filebeat
ls ${LINUX_AUDITD} >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${LINUX_AUDITD}/$line > update/$title/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/filebeat/$line;
done < txt-rules/$title-rules.txt

# Linux Mod Security
title=linux-modsec
mkdir -p update/$title/filebeat
ls ${LINUX_MODSEC} >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${LINUX_MODSEC}/$line > update/$title/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/filebeat/$line;
done < txt-rules/$title-rules.txt

# Network
title=network
mkdir -p update/$title/filebeat
ls ${NETWORK} >> txt-rules/$title-rules.txt
sed -e 's/cisco//g' txt-rules/$title-rules.txt
sed -e 's/zeek//g' txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${NETWORK}/$line > update/$title/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/filebeat/$line;
done < txt-rules/$title-rules.txt

# Proxy
title=proxy
mkdir -p update/$title/filebeat
ls ${PROXY} >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${PROXY}/$line > update/$title/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/filebeat/$line;
done < txt-rules/$title-rules.txt

# web
title=web
mkdir -p update/$title/filebeat
ls ${WEB} >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WEB}/$line > update/$title/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/filebeat/$line;
done < txt-rules/$title-rules.txt

# Windows Built in
title=windows
title2=builtin
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title2-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title2-rules.txt

# Windows Remote Threat
title=windows
title2=create_remote_thread
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title2-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title2-rules.txt

# Windows Stream Hash
title=windows
title2=create_stream_hash
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title2-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title2-rules.txt

# Windows dns 
title=windows
title2=dns_query
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows driver load
title=windows
title2=driver_load
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows file delete
title=windows
title2=file_delete
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows Image Load
title=windows
title2=image_load
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows Malware
title=windows
title2=malware
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows Network_connection
title=windows
title2=network_connection
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows other
title=windows
title2=other
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows pipes
title=windows
title2=pipe_created
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows powershell
title=windows
title2=powershell
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows Process Access
title=windows
title2=process_access
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows process Creation
title=windows
title2=process_creation
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows Raw Threads
title=windows
title2=raw_access_thread
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows Registry
title=windows
title2=registry_event
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows Sysmon
title=windows
title2=sysmon
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt

# Windows wmi
title=windows
title2=wmi_event
mkdir -p update/$title/$title2/filebeat
mkdir update/$title/$title2/winlogbeat
ls ${WINDOWS}/$title2 >> txt-rules/$title-rules.txt
while read -r line;
do
  sigmac -t elastalert -c ecs-filebeat ${WINDOWS}/$title2/$line > update/$title/$title2/filebeat/$line && \
  sigmac -t elastalert -c winlogbeat ${WINDOWS}/$title2/$line > update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/filebeat/$line && \
  echo "import: BaseHive.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseTeams.config" >> update/$title/$title2/winlogbeat/$line && \
  echo "import: BaseRule.config" >> update/$title/$title2/winlogbeat/$line;
done < txt-rules/$title-rules.txt
 