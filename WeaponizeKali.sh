#!/usr/bin/env bash

nocolor="\033[0m"
green="\033[0;32m"
yellow="\033[0;33m"
red="\033[0;31m"
red_bold="\033[1;31m"
blue="\033[0;34m"
light_gray="\033[0;37m"
dark_gray="\033[1;30m"
magenta="\033[1;35m"

SITE="https://github.com/snovvcrash/WeaponizeKali.sh"
VERSION="0.2"

echo -e $red_bold   "                                                          )                               " $nocolor
echo -e $red_bold   " (  (                                                  ( /(       (                )      " $nocolor
echo -e $red_bold   " )\))(   '   (     )                    (         (    )\())   )  )\ (          ( /(      " $nocolor
echo -e $red_bold   "((_)()\ )   ))\ ( /(  \`  )    (    (    )\  (    ))\  ((_)\ ( /( ((_))\     (   )\())    " $nocolor
echo -e $red_bold   "_(())\_)() /((_))(_)) /(/(    )\   )\ )((_) )\  /((_) _ ((_))(_)) _ ((_)    )\ ((_)\      " $nocolor
echo -e $light_gray "\ \((_)/ /(_)) ((_)_ ((_)_\  ((_) _(_/( (_)((_)(_))  | |/ /((_)_ | | (_)   ((_)| |(_)     " $nocolor
echo -e $light_gray " \ \/\/ / / -_)/ _\` || '_ \)/ _ \| ' \))| ||_ // -_) | ' < / _\` || | | | _ (_-<| ' \    " $nocolor
echo -e $light_gray "  \_/\_/  \___|\__,_|| .__/ \___/|_||_| |_|/__|\___| |_|\_\\\\\__,_||_| |_|(_)/__/|_||_|  " $nocolor
echo -e $light_gray "                     |_|                                                                  " $nocolor
echo                "                            \"the more tools you install, the more you are able to PWN\""
echo -e "                           ${magenta}{${dark_gray} ${SITE} ${magenta}} ${magenta}{${dark_gray} v${VERSION} ${magenta}}" $nocolor
echo

# -----------------------------------------------------------------------------
# ----------------------------------- Init ------------------------------------
# -----------------------------------------------------------------------------

filesystem() {
	rm -rf {tools,www}
	mkdir {tools,www}
}

# -----------------------------------------------------------------------------
# --------------------------------- Messages ----------------------------------
# -----------------------------------------------------------------------------

info() {
	msg=$1
	echo -e "${blue}[*] $msg" $nocolor
}

success() {
	msg=$1
	echo -e "${green}[+] $msg" $nocolor
}

warning() {
	msg=$1
	echo -e "${yellow}[!] $msg" $nocolor
}

fail() {
	msg=$1
	echo -e "${red}[-] $msg" $nocolor
}

# -----------------------------------------------------------------------------
# ---------------------------------- Helpers ----------------------------------
# -----------------------------------------------------------------------------

_pushd() {
	pushd $1 2>&1 > /dev/null
}

_popd() {
	popd 2>&1 > /dev/null
}

installDebPackage() {
	pkg_name=$1
	if ! /usr/bin/dpkg-query -W -f='${Status}' $pkg_name 2>&1 | /bin/grep "ok installed" > /dev/null; then
		warning "$pkg_name not found, installing..."
		sudo apt install $pkg_name -y
	else
		success "Installed deb package: $pkg_name"
	fi
}

installPipPackage() {
	V=$1
	pkg_name=$2
	if ! which $pkg_name > /dev/null 2>&1; then
		warning "[!] $pkg_name not found, installing..."

		sudo "python${V}" -m pip install $pkg_name --upgrade
	else
		success "Installed pip package: $pkg_name"
	fi
}

cloneRepository() {
	url=$1
	repo_name=${url##*/}
	repo_name=${repo_name%.*}
	if git clone -q $url $repo_name; then
		success "Cloned repository: $repo_name"
	else
		fail "Failed to clone repository: $repo_name"
	fi
}

downloadRawFile() {
	url=$1
	filename=$2
	if curl -Ls $url > $filename; then
		success "Downloaded raw file: $filename"
	else
		fail "Failed to download raw file: $filename"
	fi
}

downloadRelease() {
	full_repo_name=$1
	release_name=$2
	filename=$3
	if curl -Ls "https://api.github.com/repos/$full_repo_name/releases/latest" | jq -r '.assets[].browser_download_url' | grep $release_name | wget -O $filename -qi -; then
		success "Downloaded release: $filename"
	else
		fail "Failed to download release: $filename"
	fi
}

# -----------------------------------------------------------------------------
# ------------------------------- Dependencies --------------------------------
# -----------------------------------------------------------------------------

_jq() {
	installDebPackage jq
}

_python2-pip() {
	curl https://bootstrap.pypa.io/get-pip.py | sudo python
	sudo python -m pip install setuptools --upgrade
}

_python2-dev() {
	installDebPackage python-dev
}

_python3-pip() {
	installDebPackage python3-pip
}

_python3-venv() {
	installDebPackage python3-venv
}

_setuptools() {
	installPipPackage 2 setuptools
	installPipPackage 3 setuptools
}

_pipenv() {
	installPipPackage 3 pipenv
}

_poetry() {
	installPipPackage 3 poetry
}

_pipx() {
	installPipPackage 3 pipx
	pipx ensurepath
}

python2-impacket() {
	installPipPackage 2 impacket
}

dependencies() {
	_jq
	_python2-pip
	_python2-dev
	_python3-pip
	_python3-venv
	_setuptools
	_pipenv
	_poetry
	_pipx
	python2-impacket
}

# -----------------------------------------------------------------------------
# ----------------------------------- tools -----------------------------------
# -----------------------------------------------------------------------------

BloodHound.py() {
	pipx install "git+https://github.com/fox-it/BloodHound.py.git" -f
}

BloodHound() {
	_pushd tools
	downloadRelease "BloodHoundAD/BloodHound" BloodHound-linux-x64 BloodHound-linux-x64.zip
	unzip -q BloodHound-linux-x64.zip
	mv BloodHound-linux-x64 BloodHound
	rm BloodHound-linux-x64.zip
	cd BloodHound
	sudo chown root:root chrome-sandbox
	sudo chmod 4755 chrome-sandbox
	_popd
}

CVE-2020-1472-checker() {
	_pushd tools
	cloneRepository "https://github.com/SecuraBV/CVE-2020-1472.git"
	mv CVE-2020-1472 CVE-2020-1472-checker
	cd CVE-2020-1472-checker
	# pipenv install -r requirements.txt
	pip3 install -r requirements.txt # pipenv fails on this one
	_popd
}

CrackMapExec() {
	pipx install "git+https://github.com/byt3bl33d3r/CrackMapExec.git" -f
}

Ebowla() {
	_pushd tools
	cloneRepository "https://github.com/Genetic-Malware/Ebowla.git"
	installDebPackage golang
	installDebPackage mingw-w64
	installDebPackage wine
	installPipPackage 2 configobj
	installPipPackage 2 pyparsing
	installPipPackage 2 pycrypto
	_popd
}

Empire() {
	_pushd tools
	cloneRepository "https://github.com/BC-SECURITY/Empire.git"
	cd Empire
	sudo STAGING_KEY=`echo 'w34p0n1z3k4l1' | md5sum | cut -d' ' -f1` ./setup/install.sh
	sudo poetry install
	echo $'#!/usr/bin/env bash\n\nsudo poetry run python empire' > run_empire.sh
	chmod +x run_empire.sh 
	_popd
}

LDAPPER() {
	_pushd tools
	cloneRepository "https://github.com/shellster/LDAPPER.git"
	cd LDAPPER
	pipenv install -r requirements.txt
	_popd
}

PrivExchange() {
	_pushd tools
	cloneRepository "https://github.com/dirkjanm/PrivExchange.git"
	_popd
}

Responder() {
	_pushd tools
	cloneRepository "https://github.com/lgandx/Responder.git"
	_popd
}

TrustVisualizer() {
	_pushd tools
	cloneRepository "https://github.com/HarmJ0y/TrustVisualizer.git"
	cd TrustVisualizer
	pipenv install networkx
	_popd
}

Windows-Exploit-Suggester() {
	_pushd tools
	cloneRepository "https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git"
	_popd
}

aclpwn.py() {
	pipx install "git+https://github.com/fox-it/aclpwn.py.git" -f
}

adidnsdump() {
	pipx install "git+https://github.com/dirkjanm/adidnsdump.git" -f
}

bettercap() {
	_pushd tools
	mkdir bettercap
	cd bettercap
	downloadRelease "bettercap/bettercap" bettercap_linux_amd64.*.zip bettercap.zip
	unzip -q bettercap.zip
	rm bettercap*.sha256 bettercap.zip
	mv bettercap* bettercap
	chmod +x bettercap
	_popd
}

chisel-tools() {
	_pushd tools
	mkdir chisel
	cd chisel
	downloadRelease "jpillora/chisel" chisel.*linux_amd64.gz chisel.gz
	gunzip chisel.gz
	mv chisel* chisel
	chmod +x chisel
	_popd
}

crowbar() {
	pipx install "git+https://github.com/galkan/crowbar.git" -f
}

cve-2019-1040-scanner() {
	_pushd tools
	mkdir cve-2019-1040-scanner
	cd cve-2019-1040-scanner
	downloadRawFile "https://github.com/fox-it/cve-2019-1040-scanner/raw/master/scan.py" CVE-2019-1040-scanner.py
	chmod +x CVE-2019-1040-scanner.py
	_popd
}

dementor.py() {
	_pushd tools
	mkdir dementor
	cd dementor
	downloadRawFile "https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc/raw/7c7f09ea46eff4ede636f69c00c6dfef0541cd14/dementor.py" dementor.py
	_popd
}

dsniff() {
	sudo sysctl -w net.ipv4.ip_forward=1
	installDebPackage dsniff
}

enum4linux-ng() {
	_pushd tools
	cloneRepository "https://github.com/cddmp/enum4linux-ng.git"
	cd enum4linux-ng
	pipenv install -r requirements.txt
	_popd
}

evil-winrm() {
	sudo gem install evil-winrm
}

gateway-finder-imp() {
	_pushd tools
	cloneRepository "https://github.com/whitel1st/gateway-finder-imp.git"
	cd gateway-finder-imp
	pipenv install -r requirements.txt
	_popd
}

gitjacker() {
	_pushd tools
	mkdir gitjacker
	cd gitjacker
	downloadRelease "liamg/gitjacker" gitjacker-linux-amd64 gitjacker
	chmod +x gitjacker
	_popd
}

htbenum-tools() {
	_pushd tools
	cloneRepository "https://github.com/SolomonSklash/htbenum.git"
	_popd
}

impacket() {
	pipx install "git+https://github.com/SecureAuthCorp/impacket.git" -f
}

kerbrute() {
	_pushd tools
	mkdir kerbrute
	cd kerbrute
	downloadRelease "ropnop/kerbrute" kerbrute_linux_amd64 kerbrute
	chmod +x kerbrute
	_popd
}

mitm6() {
	pipx install "git+https://github.com/fox-it/mitm6.git" -f
}

nullinux() {
	_pushd tools
	cloneRepository "https://github.com/m8r0wn/nullinux.git"
	cd nullinux
	sudo bash setup.sh
	_popd
}

pypykatz() {
	pipx install "git+https://github.com/skelsec/pypykatz.git" -f
}

pywerview() {
	_pushd tools
	cloneRepository "https://github.com/the-useless-one/pywerview.git"
	cd pywerview
	pipenv install -r requirements.txt --python /usr/bin/python
	_popd
}

rbcd-attack() {
	_pushd tools
	cloneRepository "https://github.com/tothi/rbcd-attack.git"
	_popd
}

rbcd_permissions() {
	_pushd tools
	cloneRepository "https://github.com/NinjaStyle82/rbcd_permissions.git"
	_popd
}

rdp-tunnel-tools() {
	_pushd tools
	cloneRepository "https://github.com/NotMedic/rdp-tunnel.git"
	_popd
}

updog() {
	pipx install "git+https://github.com/sc0tfree/updog.git" -f
}

tools() {
	BloodHound
	BloodHound.py
	CVE-2020-1472-checker
	CrackMapExec
	Ebowla
	Empire
	LDAPPER
	PrivExchange
	Responder
	TrustVisualizer
	Windows-Exploit-Suggester
	aclpwn.py
	adidnsdump
	bettercap
	chisel-tools
	crowbar
	cve-2019-1040-scanner
	dementor.py
	dsniff
	enum4linux-ng
	evil-winrm
	gateway-finder-imp
	gitjacker
	htbenum-tools
	impacket
	kerbrute
	mitm6
	nullinux
	pypykatz
	pywerview
	rbcd-attack
	rbcd_permissions
	rdp-tunnel-tools
	updog
}

# -----------------------------------------------------------------------------
# ------------------------------------ www ------------------------------------
# -----------------------------------------------------------------------------

Bypass-AMSI() {
	_pushd www
	downloadRawFile "https://gist.github.com/snovvcrash/5c9ee38bb9a8802a674ec3d3d33b4717/raw/5c77510505f505db8ac1453c60ee6fc34a8e6d59/Bypass-AMSI.ps1" bypass-amsi.ps1
	_popd
}

Bypass-UAC() {
	_pushd www
	downloadRawFile "https://gist.github.com/snovvcrash/362be57caaa167e7f5667156ac80f445/raw/1990959bc80b56179863aede06695bc499249744/Bypass-UAC.ps1" bypass-uac.ps1
	_popd
}

Discover-PSMSExchangeServers() {
	_pushd www
	downloadRawFile "https://github.com/PyroTek3/PowerShell-AD-Recon/raw/master/Discover-PSMSExchangeServers" discover-psmsexchangeservers.ps1
	_popd
}

Discover-PSMSSQLServers() {
	_pushd www
	downloadRawFile "https://github.com/PyroTek3/PowerShell-AD-Recon/raw/master/Discover-PSMSSQLServers" discover-psmssqlservers.ps1
	_popd
}

DomainPasswordSpray() {
	_pushd www
	downloadRawFile "https://github.com/dafthack/DomainPasswordSpray/raw/master/DomainPasswordSpray.ps1" domainpasswordspray.ps1
	_popd
}

Intercepter-NG() {
	_pushd www
	downloadRawFile "http://sniff.su/Intercepter-NG.v1.0+.zip" intercepter-ng.zip
	_popd
}

Inveigh() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Inveigh/raw/master/Inveigh-Relay.ps1" inveigh-relay.ps1
	downloadRawFile "https://github.com/Kevin-Robertson/Inveigh/raw/master/Inveigh.ps1" inveigh.ps1
	_popd
}

InveighZero() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_x64/Inveigh.exe" inveighzero.exe
	_popd
}

Invoke-ACLPwn() {
	_pushd www
	downloadRawFile "https://github.com/fox-it/Invoke-ACLPwn/raw/master/Invoke-ACLPwn.ps1" invoke-aclpwn.ps1
	_popd
}

Invoke-Kerberoast() {
	_pushd www
	downloadRawFile "https://github.com/BC-SECURITY/Empire/raw/master/data/module_source/credentials/Invoke-Kerberoast.ps1" invoke-kerberoast.ps1
	_popd
}

Invoke-Mimikatz() {
	_pushd www
	downloadRawFile "https://github.com/BC-SECURITY/Empire/raw/master/data/module_source/credentials/Invoke-Mimikatz.ps1" invoke-mimikatz.ps1
	_popd
}

Invoke-Portscan() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/Invoke-Portscan.ps1" invoke-portscan.ps1
	_popd
}

Invoke-RunasCs() {
	_pushd www
	downloadRawFile "https://github.com/antonioCoco/RunasCs/raw/master/Invoke-RunasCs.ps1" invoke-runascs.ps1
	_popd
}

Invoke-SMBClient() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBClient.ps1" invoke-smbclient.ps1
	_popd
}

Invoke-SMBEnum() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBEnum.ps1" invoke-smbenum.ps1
	_popd
}

Invoke-SMBExec() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBExec.ps1" invoke-smbexec.ps1
	_popd
}

Invoke-WMIExec() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-WMIExec.ps1" invoke-wmiexec.ps1
	_popd
}

Out-EncryptedScript() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellMafia/PowerSploit/raw/master/ScriptModification/Out-EncryptedScript.ps1" out-encryptedscript.ps1
	_popd
}

PowerUp() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellMafia/PowerSploit/raw/master/Privesc/PowerUp.ps1" powerup.ps1
	_popd
}

PowerUpSQL() {
	_pushd www
	downloadRawFile "https://github.com/NetSPI/PowerUpSQL/raw/master/PowerUpSQL.ps1" powerupsql.ps1
	_popd
}

PowerView2() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellEmpire/PowerTools/raw/master/PowerView/powerview.ps1" powerview2.ps1
	_popd
}

PowerView3() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1" powerview3.ps1
	_popd
}

PowerView3-GPO() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellMafia/PowerSploit/raw/26a0757612e5654b4f792b012ab8f10f95d391c9/Recon/PowerView.ps1" powerview3-gpo.ps1
	_popd
}

PowerView4() {
	_pushd www
	downloadRawFile "https://github.com/ZeroDayLab/PowerSploit/raw/master/Recon/PowerView.ps1" powerview4.ps1
	_popd
}

Powermad() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Powermad/raw/master/Powermad.ps1" powermad.ps1
	_popd
}

PrivescCheck() {
	_pushd www
	downloadRawFile "https://github.com/itm4n/PrivescCheck/raw/master/PrivescCheck.ps1" privesccheck.ps1
	_popd
}

ProcDump() {
	_pushd www
	downloadRawFile "https://download.sysinternals.com/files/Procdump.zip" procdump.zip
	unzip -q procdump.zip
	mv procdump64.exe procdump.exe
	rm Eula.txt procdump64a.exe procdump.zip
	_popd
}

Rubeus() {
	_pushd www
	downloadRawFile "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe" rubeus.exe
	downloadRawFile "https://github.com/BC-SECURITY/Empire/raw/master/data/module_source/credentials/Invoke-Rubeus.ps1" invoke-rubeus.ps1
	_popd
}

Seatbelt() {
	_pushd www
	downloadRawFile "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe" seatbelt.exe
	_popd
}

SessionGopher() {
	_pushd www
	downloadRawFile "https://github.com/Arvanaghi/SessionGopher/raw/master/SessionGopher.ps1" sessiongopher.ps1
	_popd
}

Set-GpoStatus() {
	_pushd www
	downloadRawFile "https://gist.github.com/snovvcrash/ecdc639b061fe787617d8d92d8549801/raw/047115ad321f3a7f918e31cffb005d276dd1e8df/Set-GpoStatus.ps1" set-gpostatus.ps1
	_popd
}

SharpGPOAbuse() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_x64/SharpGPOAbuse.exe" sharpgpoabuse.exe
	_popd
}

SharpHound() {
	_pushd www
	downloadRawFile "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe" sharphound.exe
	downloadRawFile "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.ps1" sharphound.ps1
	_popd
}

Sherlock() {
	_pushd www
	downloadRawFile "https://github.com/rasta-mouse/Sherlock/raw/master/Sherlock.ps1" sherlock.ps1
	_popd
}

SpoolSample() {
	_pushd www
	downloadRawFile "https://github.com/BlackDiverX/WinTools/raw/master/SpoolSample-Printerbug/SpoolSample.exe" spoolsample.exe
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/PowerSharpPack/raw/master/PowerSharpBinaries/Invoke-Spoolsample.ps1" invoke-spoolsample.ps1
	_popd
}

Watson() {
	_pushd www
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/PowerSharpPack/raw/master/PowerSharpBinaries/Invoke-SharpWatson.ps1" invoke-sharpwatson.ps1
	_popd
}

WinPwn() {
	_pushd www
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/WinPwn.ps1" winpwn.ps1
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/ObfusWinPwn.ps1" obfuswinpwn.ps1
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/Obfus_SecurePS_WinPwn.ps1" obfus-secureps-winpwn.ps1
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/Offline_WinPwn.ps1" offline-winpwn.ps1
	_popd
}

chisel-www() {
	_pushd www
	mkdir tmp1
	cd tmp1
	downloadRelease "jpillora/chisel" chisel.*linux_amd64.gz chisel.gz
	gunzip chisel.gz
	mv chisel* ../chisel
	cd ..
	mkdir tmp2
	cd tmp2
	downloadRelease "jpillora/chisel" chisel.*windows_amd64.gz chisel.exe.gz
	gunzip chisel.exe.gz
	mv chisel*.exe ../chisel.exe
	cd ..
	rm -rf tmp1 tmp2
	_popd
}

htbenum-www() {
	_pushd www
	downloadRawFile "https://github.com/SolomonSklash/htbenum/raw/master/htbenum.sh" htbenum.sh
	_popd
}

linux-exploit-suggester() {
	_pushd www
	downloadRawFile "https://github.com/mzet-/linux-exploit-suggester/raw/master/linux-exploit-suggester.sh" les.sh
	_popd
}

mimikatz() {
	_pushd www
	downloadRelease "gentilkiwi/mimikatz" mimikatz_trunk.zip mimikatz.zip
	_popd
}

netcat-win() {
	_pushd www
	downloadRawFile "https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip" nc.zip
	unzip -q nc.zip
	rm doexec.c generic.h getopt.c getopt.h hobbit.txt license.txt Makefile netcat.c nc.zip readme.txt
	mv nc64.exe nc.exe
	_popd
}

plink() {
	_pushd www
	downloadRawFile "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" plink.exe
	_popd
}

powercat() {
	_pushd www
	downloadRawFile "https://github.com/besimorhino/powercat/raw/master/powercat.ps1" powercat.ps1
	_popd
}

pspy() {
	_pushd www
	downloadRelease "DominicBreuker/pspy" pspy64 pspy
	_popd
}

rdp-tunnel-www() {
	_pushd www
	downloadRawFile "https://github.com/NotMedic/rdp-tunnel/raw/master/rdp2tcp.exe" rdp2tcp.exe
	_popd
}

winPEAS() {
	_pushd www
	downloadRawFile "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe" winpeas.exe
	downloadRawFile "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASx64.exe" winpeas-obf.exe
	downloadRawFile "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Release/Dotfuscated/winPEAS.exe" winpeas-dotobf.exe
	downloadRawFile "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/linPEAS/linpeas.sh" linpeas.sh
	_popd
}

www() {
	Bypass-AMSI
	Bypass-UAC
	Discover-PSMSExchangeServers
	Discover-PSMSSQLServers
	DomainPasswordSpray
	Intercepter-NG
	Inveigh
	InveighZero
	Invoke-ACLPwn
	Invoke-Kerberoast
	Invoke-Mimikatz
	Invoke-Portscan
	Invoke-RunasCs
	Invoke-SMBClient
	Invoke-SMBEnum
	Invoke-SMBExec
	Invoke-WMIExec
	Out-EncryptedScript
	PowerUp
	PowerUpSQL
	PowerView2
	PowerView3
	PowerView3-GPO
	PowerView4
	Powermad
	PrivescCheck
	ProcDump
	Rubeus
	Seatbelt
	SessionGopher
	Set-GpoStatus
	SharpGPOAbuse
	SharpHound
	Sherlock
	SpoolSample
	Watson
	WinPwn
	chisel-www
	htbenum-www
	linux-exploit-suggester
	mimikatz
	netcat-win
	plink
	powercat
	pspy
	rdp-tunnel-www
	winPEAS
}

# -----------------------------------------------------------------------------
# ----------------------------------- Help ------------------------------------
# -----------------------------------------------------------------------------

help() {
	echo "usage: WeaponizeKali.sh [-h] [-i] [-d] [-t] [w]"
	echo
	echo "optional arguments:"
	echo "  -h                    show this help message and exit"
	echo "  -i                    initialize filesystem (re-creates ./tools and ./www directories)"
	echo "  -d                    resolve dependencies"
	echo "  -t                    call \"tools\" module"
	echo "  -w                    call \"www\" module"
}

# -----------------------------------------------------------------------------
# ----------------------------------- Main ------------------------------------
# -----------------------------------------------------------------------------

while getopts "hidtw" opt; do
	case "$opt" in
	h)
		call_help=1
		;;
	i)
		init_filesystem=1
		;;
	d)
		resolve_dependencies=1
		;;
	t)
		call_tools=1
		;;
	w)
		call_www=1
		;;
	esac
done

if [[ "$call_help" ]]; then
	help
	exit
fi

if [[ "$init_filesystem" ]]; then
	filesystem
fi

if [[ "$resolve_dependencies" ]]; then
	echo -e "${red}############################## dependencies ##############################"
	dependencies
fi

if [[ "$call_tools" ]]; then
	echo -e "${red}################################# tools ##################################"
	tools
fi

if [[ "$call_www" ]]; then
	echo -e "${red}################################## www ###################################"
	www
fi
