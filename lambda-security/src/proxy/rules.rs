
use regex::Regex;
use hyper::body::Bytes;
use std::str;

//TODO introduce block/monitoring mode per rule
//TODO deny lists, incl 941180
//TODO performance cost per rule and class
//TODO rules_outbound
//TODO global config enable/disable by severity, class, inbound/outbound, etc
//TODO regex of libinjection for sqli and xss "detectSQLi" libs (no regex exists)

#[derive(Debug)]
pub struct Rule {
    pub id: i32,
    pub class: String,
    pub desc: String,
    pub severity: String,
    pub re: String,
}


pub fn rules_inbound() -> Vec<Rule> {
    let rules = vec![

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf#L23
        // [ Encoded /../ Payloads ]
        // index 0
        Rule {
            id: 930100,
            class: "LFI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Path Traversal Attack (/../) or (/.../)".to_string(),
            re: r"(?i)(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[5-6]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))(?:\.(?:%0[0-1]|\?)?|\?\.?|%(?:2(?:(?:5(?:2|c0%25a))?e|%45)|c0(?:\.|%[25-6ae-f]e)|u(?:(?:ff0|002)e|2024)|%32(?:%(?:%6|4)5|E)|(?:e|f(?:(?:8|c%80)%8)?0%8)0%80%ae)|0x2e){2,3}(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[5-6]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))".to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf#L26
        // index 1
        Rule {
            id: 931100,
            class: "RFI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address".to_string(),
            re: r"(?i:file|ftps?|https?)://(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})".to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf#L57
        // index 2
        Rule {
            id: 931110,
            class: "RFI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload".to_string(),
            re: r"(?i)(?:\binclude\s*\([^)]*|mosConfig_absolute_path|_CONF\[path\]|_SERVER\[DOCUMENT_ROOT\]|GALLERY_BASEDIR|path\[docroot\]|appserv_root|config\[root_dir\])=(?:file|ftps?|https?)://".to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf#L77C20-L77C48
        // index 3
        Rule {
            id: 931120,
            class: "RFI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)".to_string(),
            re: r"(?i:file|ftps?|https?).*?\?+".to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf#L116
        // index 4
        Rule {
            id: 931130,
            class: "RFI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link".to_string(),
            re: r"(?i)(?:(?:url|jar):)?(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://(?:[^@]+@)?([^/]*)".to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L121C1-L121C1
        // index 5
        Rule {
            id: 932230,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix Command Injection (2-3 chars)".to_string(),
            re: r#"(?i)(?:t["')\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|[\n\r;`\{]|\|\|?|&&?|\$(?:\(\(?|\{)|[<>]\(|\([\s\v]*\))[\s\v]*(?:[\$\{]|(?:[\s\v]*\(|!)[\s\v]*|[0-9A-Z_a-z]+=(?:[^\s\v]*|\$(?:.*|.*)|[<>].*|'.*'|".*")[\s\v]+)*[\s\v]*["']*(?:["'-\+\--9\?A-\]_a-z\|]+/)?["'\x5c]*(?:7["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[arx])?|(?:(?:b["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z|x)["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z|h["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p)["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[\s\v&\),<>\|].*|[ckz]["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?h|d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?f|e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:n["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?v|s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?h)|f["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[dg]|g["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:c["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?c["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:[&,<>\|]|(?:[\--\.0-9A-Z_a-z]["'\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\*\-0-9\?-@_a-\{]*)?\x5c?)+[\s\v&,<>\|]).*|p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?g)|i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?r["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?b|l["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:s|z["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:4|[\s\v&\),<>\|].*))|p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:h["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[\s\v&\),<>\|].*|w["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d|x["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z)|r["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?c(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[\s\v&\),<>\|].*)?|s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:c["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p|(?:e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d|(?:s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?)?h)["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[\s\v&\),<>\|].*|v["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?n)|u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p|w["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?3["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m)\b"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L181C1-L181C1 
        // index 6
        Rule {
            id: 932235,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix Command Injection (command without evasion)".to_string(),
            re: r#"(?i)(?:t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|[\n\r;`\{]|\|\|?|&&?|\$(?:\(\(?|\{)|[<>]\(|\([\s\v]*\))[\s\v]*(?:[\$\{]|(?:[\s\v]*\(|!)[\s\v]*|[0-9A-Z_a-z]+=(?:[^\s\v]*|\$(?:.*|.*)|[<>].*|'.*'|".*")[\s\v]+)*[\s\v]*["']*(?:["'-\+\--9\?A-\]_a-z\|]+/)?["'\x5c]*(?:(?:HEAD|POST|y(?:arn|elp))[\s\v&\)<>\|]|a(?:dd(?:group|user)|getty|l(?:ias|pine)[\s\v&\)<>\|]|nsible-playbook|pt(?:-get|itude[\s\v&\)<>\|])|r(?:ch[\s\v&\)<>\|]|ia2c)|s(?:cii(?:-xfr|85)|pell)|tobm|xel)|b(?:a(?:s(?:e(?:32|64|n(?:ame[\s\v&\)<>\|]|c))|h[\s\v&\)<>\|])|tch[\s\v&\)<>\|])|lkid|pftrace|r(?:eaksw|idge[\s\v&\)<>\|])|sd(?:cat|iff|tar)|u(?:iltin|n(?:dler[\s\v&\)<>\|]|zip2)|s(?:ctl|ybox))|y(?:ebug|obu)|z(?:c(?:at|mp)|diff|e(?:grep|xe)|f?grep|ip2(?:recover)?|less|more))|c(?:a(?:ncel|psh)[\s\v&\)<>\|]|ertbot|h(?:attr|(?:dir|root)[\s\v&\)<>\|]|eck_(?:by_ssh|cups|log|memory|raid|s(?:sl_cert|tatusfile))|(?:flag|pas)s|g(?:passwd|rp)|mod|o(?:om|wn)|sh)|lang(?:[\s\v&\)<>\|]|\+\+)|o(?:(?:b|pro)c|(?:lumn|m(?:m(?:and)?|p(?:oser|ress)))[\s\v&\)<>\|]|w(?:say|think))|p(?:an|io|ulimit)|r(?:ash[\s\v&\)<>\|]|on(?:tab)?)|s(?:plit|vtool)|u(?:psfilter|rl[\s\v&\)<>\|]))|d(?:(?:a(?:sh|te)|i(?:alog|ff))[\s\v&\)<>\|]|hclient|m(?:esg|idecode|setup)|o(?:as|(?:cker|ne)[\s\v&\)<>\|]|sbox)|pkg|vips)|e(?:2fsck|(?:asy_instal|va)l|cho[\s\v&\)<>\|]|fax|grep|macs|n(?:d(?:if|sw)|v-update)|sac|x(?:ec[\s\v&\)<>\|]|iftool|p(?:(?:and|(?:ec|or)t)[\s\v&\)<>\|]|r)))|f(?:acter|(?:etch|lock|unction)[\s\v&\)<>\|]|grep|i(?:le(?:[\s\v&\)<>\|]|test)|(?:n(?:d|ger)|sh)[\s\v&\)<>\|])|o(?:ld[\s\v&\)<>\|]|reach)|ping|tp(?:stats|who))|g(?:awk[\s\v&\)<>\|]|core|e(?:ni(?:e[\s\v&\)<>\|]|soimage)|tfacl[\s\v&\)<>\|])|hci|i(?:mp[\s\v&\)<>\|]|nsh)|r(?:ep[\s\v&\)<>\|]|oup(?:[\s\v&\)<>\|]|mod))|tester|unzip|z(?:cat|exe|ip))|h(?:(?:ash|i(?:ghlight|story))[\s\v&\)<>\|]|e(?:ad[\s\v&\)<>\|]|xdump)|ost(?:id|name)|ping3|t(?:digest|op|passwd))|i(?:conv|f(?:config|top)|nstall[\s\v&\)<>\|]|onice|p(?:6?tables|config)|spell)|j(?:ava[\s\v&\)<>\|]|exec|o(?:(?:bs|in)[\s\v&\)<>\|]|urnalctl)|runscript)|k(?:ill(?:[\s\v&\)<>\|]|all)|nife[\s\v&\)<>\|]|sshell)|l(?:a(?:st(?:[\s\v&\)<>\|]|comm|log(?:in)?)|tex[\s\v&\)<>\|])|dconfig|ess(?:[\s\v&\)<>\|]|echo|(?:fil|pip)e)|ftp(?:get)?|(?:inks|ynx)[\s\v&\)<>\|]|o(?:(?:ca(?:l|te)|ok)[\s\v&\)<>\|]|g(?:inctl|(?:nam|sav)e)|setup)|s(?:-F|b_release|cpu|hw|mod|of|pci|usb)|trace|ua(?:la)?tex|wp-(?:d(?:ownload|ump)|mirror|request)|z(?:4c(?:at)?|c(?:at|mp)|diff|[e-f]?grep|less|m(?:a(?:dec|info)?|ore)))|m(?:a(?:il(?:[\s\v&\)<>q\|]|x[\s\v&\)<>\|])|ke[\s\v&\)<>\|]|ster\.passwd|wk)|k(?:dir[\s\v&\)<>\|]|fifo|nod|temp)|locate|o(?:(?:re|unt)[\s\v&\)<>\|]|squitto)|sg(?:attrib|c(?:at|onv)|filter|merge|uniq)|utt[\s\v&\)<>\|]|ysql(?:admin|dump(?:slow)?|hotcopy|show)?)|n(?:a(?:no[\s\v&\)<>\|]|sm|wk)|c(?:\.(?:openbsd|traditional)|at)|e(?:ofetch|t(?:(?:c|st)at|kit-ftp|plan))|(?:ice|ull)[\s\v&\)<>\|]|map|o(?:de[\s\v&\)<>\|]|hup)|ping|roff|s(?:enter|lookup|tat))|o(?:ctave[\s\v&\)<>\|]|nintr|p(?:en(?:ssl|v(?:pn|t))|kg))|p(?:a(?:(?:cman|rted|tch)[\s\v&\)<>\|]|s(?:swd|te[\s\v&\)<>\|]))|d(?:f(?:la)?tex|ksh)|er(?:f|l(?:5|sh)?|ms[\s\v&\)<>\|])|(?:ft|gre)p|hp(?:-cgi|[57])|i(?:(?:co|ng)[\s\v&\)<>\|]|dstat|gz)|k(?:exec|g_?info|ill)|opd|rint(?:env|f[\s\v&\)<>\|])|s(?:ed|ftp|ql)|tar(?:diff|grep)?|u(?:ppet[\s\v&\)<>\|]|shd)|wd\.db|y(?:thon[^\s\v]|3?versions))|r(?:ak(?:e[\s\v&\)<>\|]|u)|bash|e(?:a(?:delf|lpath)|(?:dcarpet|name|p(?:eat|lace))[\s\v&\)<>\|]|stic)|l(?:ogin|wrap)|m(?:dir[\s\v&\)<>\|]|user)|nano|oute[\s\v&\)<>\|]|pm(?:db|(?:quer|verif)y)|sync|u(?:by[^\s\v]|n-(?:mailcap|parts))|vi(?:ew|m))|s(?:(?:ash|nap)[\s\v&\)<>\|]|c(?:hed|r(?:een|ipt)[\s\v&\)<>\|])|diff|e(?:(?:lf|rvice)[\s\v&\)<>\|]|ndmail|t(?:arch|env|facl[\s\v&\)<>\|]|sid))|ftp|h(?:\.distrib|(?:adow|ells)[\s\v&\)<>\|]|u(?:f|tdown[\s\v&\)<>\|]))|l(?:eep[\s\v&\)<>\|]|sh)|mbclient|o(?:cat|elim|(?:rt|urce)[\s\v&\)<>\|])|p(?:lit[\s\v&\)<>\|]|wd\.db)|qlite3|sh(?:-key(?:ge|sca)n|pass)|t(?:art-stop-daemon|d(?:buf|err|in|out)|r(?:ace|ings[\s\v&\)<>\|]))|udo|ys(?:ctl|tem(?:ctl|d-resolve)))|t(?:a(?:il[\s\v&\)<>f\|]|sk(?:[\s\v&\)<>\|]|set))|c(?:l?sh|p(?:dump|ing|traceroute))|elnet|ftp|ime(?:(?:out)?[\s\v&\)<>\|]|datectl)|mux|ouch[\s\v&\)<>\|]|r(?:aceroute6?|off)|shark)|u(?:limit[\s\v&\)<>\|]|n(?:ame|(?:compress|s(?:et|hare))[\s\v&\)<>\|]|expand|iq|l(?:ink[\s\v&\)<>\|]|z(?:4|ma))|(?:pig|x)z|rar|z(?:ip[\s\v&\)<>\|]|std))|p(?:2date[\s\v&\)<>\|]|date-alternatives)|ser(?:(?:ad|mo)d|del)|u(?:de|en)code)|v(?:algrind|i(?:ew[\s\v&\)<>\|]|gr|mdiff|pw|rsh)|olatility[\s\v&\)<>\|])|w(?:a(?:ll|tch)[\s\v&\)<>\|]|get|h(?:iptail[\s\v&\)<>\|]|o(?:ami|is))|i(?:reshark|sh[\s\v&\)<>\|]))|x(?:args|e(?:la)?tex|mo(?:dmap|re)|pad|term|z(?:c(?:at|mp)|d(?:ec|iff)|[e-f]?grep|less|more))|z(?:athura|c(?:at|mp)|diff|e(?:grep|ro[\s\v&\)<>\|])|f?grep|ip(?:c(?:loak|mp)|details|grep|info|(?:merg|not)e|split|tool)|less|more|run|s(?:oelim|td(?:(?:ca|m)t|grep|less)?)|ypper))"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L291
        // index 7
        Rule {
            id: 932130,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix Shell Expression Found".to_string(),
            re: r#"\$(?:\((?:.*|\(.*\))\)|\{.*\})|[<>]\(.*\)|/[0-9A-Z_a-z]*\[!?.+\]"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L419
        // index 8
        Rule {
            id: 932250,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Direct Unix Command Execution".to_string(),
            re: r#"(?i)(?:^|=)[\s\v]*(?:t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|[\$\{]|(?:[\s\v]*\(|!)[\s\v]*|[0-9A-Z_a-z]+=(?:[^\s\v]*|\$(?:.*|.*)|[<>].*|'.*'|".*")[\s\v]+)*[\s\v]*["']*(?:["'-\+\--9\?A-\]_a-z\|]+/)?["'\x5c]*(?:7["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[arx])?|(?:b["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z|x)["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z|[ckz]["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?h|d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?f|e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:n["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?v|s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?h)|f["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[dg]|g["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:c["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?c|p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?g)|(?:h["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?u|u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d)["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p|i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?r["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?b|l["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:s|z(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?4)?)|p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:h["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p|w["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d|x["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z)|r["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?c(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p)?|s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:c["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p|e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d|(?:s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?)?h|v["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?n)|w["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?3["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m)[\s\v&\)<>\|]"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L478
        // index 9
        Rule {
            id: 932260,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Direct Unix Command Execution".to_string(),
            re: r#"(?i)(?:^|=)[\s\v]*(?:t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|[\$\{]|(?:[\s\v]*\(|!)[\s\v]*|[0-9A-Z_a-z]+=(?:[^\s\v]*|\$(?:.*|.*)|[<>].*|'.*'|".*")[\s\v]+)*[\s\v]*["']*(?:["'-\+\--9\?A-\]_a-z\|]+/)?["'\x5c]*(?:a(?:ddgroup|xel)|b(?:ase(?:32|64|nc)|lkid|sd(?:cat|iff|tar)|u(?:iltin|nzip2|sybox)|yobu|z(?:c(?:at|mp)|diff|e(?:grep|xe)|f?grep|ip2(?:recover)?|less|more))|c(?:h(?:g(?:passwd|rp)|pass|sh)|lang\+\+|o(?:mm[\s\v&\)<>\|]|proc)|ron)|d(?:iff[\s\v&\)<>\|]|mesg|oas)|e(?:2fsck|grep)|f(?:grep|iletest|tp(?:stats|who))|g(?:r(?:ep[\s\v&\)<>\|]|oupmod)|unzip|z(?:cat|exe|ip))|htop|l(?:ast(?:comm|log(?:in)?)|ess(?:echo|(?:fil|pip)e)|ftp(?:get)?|osetup|s(?:-F|b_release|cpu|mod|of|pci|usb)|wp-download|z(?:4c(?:at)?|c(?:at|mp)|diff|[e-f]?grep|less|m(?:a(?:dec|info)?|ore)))|m(?:a(?:ilq|ster\.passwd)|k(?:fifo|nod|temp)|locate|ysql(?:admin|dump(?:slow)?|hotcopy|show))|n(?:c(?:\.(?:openbsd|traditional)|at)|et(?:(?:c|st)at|kit-ftp|plan)|ohup|ping|stat)|onintr|p(?:dksh|erl5?|(?:ft|gre)p|hp(?:-cgi|[57])|igz|k(?:exec|ill)|(?:op|se)d|rint(?:env|f[\s\v&\)<>\|])|tar(?:diff|grep)?|wd\.db|y(?:thon[2-3]|3?versions))|r(?:(?:bas|ealpat)h|m(?:dir[\s\v&\)<>\|]|user)|nano|sync)|s(?:diff|e(?:ndmail|t(?:env|sid))|ftp|(?:h\.distri|pwd\.d)b|ocat|td(?:err|in|out)|udo|ysctl)|t(?:ailf|c(?:p(?:ing|traceroute)|sh)|elnet|imeout[\s\v&\)<>\|]|raceroute6?)|u(?:n(?:ame|lz(?:4|ma)|(?:pig|x)z|rar|zstd)|ser(?:(?:ad|mo)d|del))|vi(?:gr|pw)|w(?:get|hoami)|x(?:args|z(?:c(?:at|mp)|d(?:ec|iff)|[e-f]?grep|less|more))|z(?:c(?:at|mp)|diff|[e-f]?grep|ip(?:c(?:loak|mp)|details|grep|info|(?:merg|not)e|split|tool)|less|more|run|std(?:(?:ca|m)t|grep|less)?))"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L518
        // index 10
        Rule {
            id: 932330,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix shell history invocation".to_string(),
            re: r#"!-\d"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L590
        // index 11
        Rule {
            id: 932170,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Shellshock (CVE-2014-6271)".to_string(),
            re: r#"\(\s*\)\s+\{"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L653 
        // index 12
        Rule {
            id: 932175,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix shell alias invocation".to_string(),
            re: r#"\ba["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?l["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?s\b[\s\v]+[!-"%',0-9@-Z_a-z]+=[^\s\v]"#.to_string()
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L962
        // index 13
        Rule {
            id: 932200,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "RCE Bypass Technique".to_string(),
            re: r#"['\*\?\x5c`][^\n/]+/|/[^/]+?['\*\?\x5c`]|\$[!#-\$\(\*\-0-9\?-\[_a-\{]"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1073
        // index 14
        Rule {
            id: 932220,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix Command Injection with pipe".to_string(),
            re: r#"(?i).\|(?:[\s\v]*|t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|[\n\r;`\{]|\|\|?|&&?|\$(?:\(\(?|\{)|[<>]\(|\([\s\v]*\))[\s\v]*(?:[\$\{]|(?:[\s\v]*\(|!)[\s\v]*|[0-9A-Z_a-z]+=(?:[^\s\v]*|\$(?:.*|.*)|[<>].*|'.*'|".*")[\s\v]+)*[\s\v]*["']*(?:["'-\+\--9\?A-\]_a-z\|]+/)?["'\x5c]*(?:7["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[arx])?|G["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?E["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?T|a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:b|(?:p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?)?t|r(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[jp])?|s(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?h)?|w["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[ks])|b["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z|c["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:[8-9]["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?9|[au]["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?t|c|(?:m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?)?p|s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?h)|d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:[dfu]|i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[gr])|e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:[bdx]|n["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?v|q["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?n|s(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?h)?)|f["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:[c-dgi]|m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?t|t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p)|g["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:[chr]["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?c|d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?b|e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m|i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?t|o|p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?g)|h["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:d|u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p)|i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:[dp]|r["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?b)|j["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:j["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?s|q)|k["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?h|l["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:d(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d)?|[nps]|u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?a|z(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?4)?)|m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?n|t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?r|v)|n["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:[cl]|e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?t|(?:p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?)?m)|o["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d|p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:[at]["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?x|d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?b|f|(?:k["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?)?g|h["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p|i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[cp]|r(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?y)?|w["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d|x["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?z)|r["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?r|c(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p)?|e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[dv]|(?:p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?)?m)|s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:c["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p|e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[dt]|[g-hu]|s(?:["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?h)?|v["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?n)|t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[cr]|b["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?l|[co]["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p|e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[ex]|i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?c)|u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p|l)|v["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m|w["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:3["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m|c)|x["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:x["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d|z)|y["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:e["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?s|u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m)|z["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p|s["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?h))"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1136
        // index 15
        Rule {
            id: 932240,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix Command Injection evasion attempt detected".to_string(),
            re: r#"(?i)[\-0-9_a-z]+(?:["'\[-\]]+|\$+[!#\*\-0-9\?-@\x5c_a-\{]+|``|[\$<>]\(\))[\s\v]*[\-0-9_a-z]+"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1179
        // index 16
        Rule {
            id: 932210,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: SQLite System Command Execution".to_string(),
            re: r#";[\s\v]*\.[\s\v]*["']?(?:a(?:rchive|uth)|b(?:a(?:ckup|il)|inary)|c(?:d|h(?:anges|eck)|lone|onnection)|d(?:atabases|b(?:config|info)|ump)|e(?:cho|qp|x(?:cel|it|p(?:ert|lain)))|f(?:ilectrl|ullschema)|he(?:aders|lp)|i(?:mpo(?:rt|ster)|ndexes|otrace)|l(?:i(?:mi|n)t|o(?:ad|g))|(?:mod|n(?:onc|ullvalu)|unmodul)e|o(?:nce|pen|utput)|p(?:arameter|r(?:int|o(?:gress|mpt)))|quit|re(?:ad|cover|store)|s(?:ave|c(?:anstats|hema)|e(?:lftest|parator|ssion)|h(?:a3sum|ell|ow)?|tats|ystem)|t(?:ables|estc(?:ase|trl)|ime(?:out|r)|race)|vfs(?:info|list|name)|width)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1221
        // index 17
        Rule {
            id: 932300,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: SMTP Command Execution".to_string(),
            re: r#"\r\n(?s:.)*?\b(?:(?i:E)(?:HLO [\--\.A-Za-z\x17f\x212a]{1,255}|XPN .{1,64})|HELO [\--\.A-Za-z\x17f\x212a]{1,255}|MAIL FROM:<.{1,64}(?i:@).{1,255}(?i:>)|(?i:R)(?:CPT TO:(?:(?i:<).{1,64}(?i:@).{1,255}(?i:>)|(?i: ))?(?i:<).{1,64}(?i:>)|SET\b)|VRFY .{1,64}(?: <.{1,64}(?i:@).{1,255}(?i:>)|(?i:@).{1,255})|AUTH [\-0-9A-Z_a-z\x17f\x212a]{1,20}(?i: )(?:(?:[\+/-9A-Z_a-z\x17f\x212a]{4})*(?:[\+/-9A-Z_a-z\x17f\x212a]{2}(?i:=)|[\+/-9A-Z_a-z\x17f\x212a]{3}))?(?i:=)|STARTTLS\b|NOOP\b(?:(?i: ).{1,255})?)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1253
        // index 18
        Rule {
            id: 932310,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: IMAP Command Execution".to_string(),
            re: r#"(?is)\r\n[0-9A-Z_a-z]{1,50}\b (?:A(?:PPEND (?:["-#%-&\*\--9A-Z\x5c_a-z]+)?(?: \([ \x5ca-z]+\))?(?: "?[0-9]{1,2}-[0-9A-Z_a-z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} [\+\-][0-9]{4}"?)? \{[0-9]{1,20}\+?\}|UTHENTICATE [\-0-9_a-z]{1,20}\r\n)|L(?:SUB (?:["-#\*\.-9A-Z_a-z~]+)? (?:["%-&\*\.-9A-Z\x5c_a-z]+)?|ISTRIGHTS (?:["%-&\*\--9A-Z\x5c_a-z]+)?)|S(?:TATUS (?:["%-&\*\--9A-Z\x5c_a-z]+)? \((?:U(?:NSEEN|IDNEXT)|MESSAGES|UIDVALIDITY|RECENT| )+\)|ETACL (?:["%-&\*\--9A-Z\x5c_a-z]+)? [\+\-][ac-eik-lpr-tw-x]+?)|UID (?:COPY|FETCH|STORE) (?:[\*,0-:]+)?|(?:(?:DELETE|GET)ACL|MYRIGHTS) (?:["%-&\*\--9A-Z\x5c_a-z]+)?)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1287
        // index 19
        Rule {
            id: 932320,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: POP3 Command Execution".to_string(),
            re: r#"(?is)\r\n.*?\b(?:(?:LIST|TOP [0-9]+)(?: [0-9]+)?|U(?:SER .+?|IDL(?: [0-9]+)?)|PASS .+?|(?:RETR|DELE) [0-9]+?|A(?:POP [0-9A-Z_a-z]+ [0-9a-f]{32}|UTH [\-0-9A-Z_]{1,20} (?:(?:[\+/-9A-Z_a-z]{4})*(?:[\+/-9A-Z_a-z]{2}=|[\+/-9A-Z_a-z]{3}))?=))"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1347
        // index 20
        Rule {
            id: 932236,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix Command Injection (command without evasion)".to_string(),
            re: r#"(?i)(?:(?:^|=)[\s\v]*(?:t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|[\$\{]|(?:[\s\v]*\(|!)[\s\v]*|[0-9A-Z_a-z]+=(?:[^\s\v]*|\$(?:.*|.*)|[<>].*|'.*'|".*")[\s\v]+)*|(?:t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|[\n\r;`\{]|\|\|?|&&?|\$(?:\(\(?|\{)|[<>]\(|\([\s\v]*\))[\s\v]*(?:[\$\{]|(?:[\s\v]*\(|!)[\s\v]*|[0-9A-Z_a-z]+=(?:[^\s\v]*|\$(?:.*|.*)|[<>].*|'.*'|".*")[\s\v]+)*)[\s\v]*["']*(?:["'-\+\--9\?A-\]_a-z\|]+/)?["'\x5c]*(?:7z[arx]?|(?:(?:GE|POS)T|HEAD)[\s\v&\)<>\|]|a(?:(?:b|w[ks]|l(?:ias|pine))[\s\v&\)<>\|]|pt(?:[\s\v&\)<>\|]|-get)|r(?:[\s\v&\)<>j\|]|(?:p|ch)[\s\v&\)<>\|]|ia2c)|s(?:h?[\s\v&\)<>\|]|cii(?:-xfr|85)|pell)|t(?:[\s\v&\)<>\|]|obm)|dd(?:group|user)|getty|nsible-playbook|xel)|b(?:z(?:z[\s\v&\)<>\|]|c(?:at|mp)|diff|e(?:grep|xe)|f?grep|ip2(?:recover)?|less|more)|a(?:s(?:e(?:32|64|n(?:ame[\s\v&\)<>\|]|c))|h[\s\v&\)<>\|])|tch[\s\v&\)<>\|])|lkid|pftrace|r(?:eaksw|idge[\s\v&\)<>\|])|sd(?:cat|iff|tar)|u(?:iltin|n(?:dler[\s\v&\)<>\|]|zip2)|s(?:ctl|ybox))|y(?:ebug|obu))|c(?:[8-9]9|(?:a(?:t|ncel|psh)|c)[\s\v&\)<>\|]|mp|p(?:[\s\v&\)<>\|]|an|io|ulimit)|s(?:h|plit|vtool)|u(?:(?:t|rl)[\s\v&\)<>\|]|psfilter)|ertbot|h(?:attr|(?:dir|root)[\s\v&\)<>\|]|eck_(?:by_ssh|cups|log|memory|raid|s(?:sl_cert|tatusfile))|(?:flag|pas)s|g(?:passwd|rp)|mod|o(?:om|wn)|sh)|lang(?:[\s\v&\)<>\|]|\+\+)|o(?:(?:b|pro)c|(?:lumn|m(?:m(?:and)?|p(?:oser|ress)))[\s\v&\)<>\|]|w(?:say|think))|r(?:ash[\s\v&\)<>\|]|on(?:tab)?))|d(?:(?:[du]|i(?:(?:alo)?g|r|ff)|a(?:sh|te))[\s\v&\)<>\|]|f|hclient|m(?:esg|idecode|setup)|o(?:as|(?:cker|ne)[\s\v&\)<>\|]|sbox)|pkg|vips)|e(?:(?:[bd]|cho)[\s\v&\)<>\|]|n(?:v(?:-update)?|d(?:if|sw))|qn|s(?:[\s\v&\)<>h\|]|ac)|x(?:(?:ec)?[\s\v&\)<>\|]|iftool|p(?:(?:and|(?:ec|or)t)[\s\v&\)<>\|]|r))|2fsck|(?:asy_instal|va)l|fax|grep|macs)|f(?:(?:c|etch|lock|unction)[\s\v&\)<>\|]|d|g(?:rep)?|i(?:(?:n(?:d|ger)|sh)?[\s\v&\)<>\|]|le(?:[\s\v&\)<>\|]|test))|mt|tp(?:[\s\v&\)<>\|]|stats|who)|acter|o(?:ld[\s\v&\)<>\|]|reach)|ping)|g(?:c(?:c[^\s\v]|ore)|db|e(?:(?:m|tfacl)[\s\v&\)<>\|]|ni(?:e[\s\v&\)<>\|]|soimage))|hci?|i(?:(?:t|mp)[\s\v&\)<>\|]|nsh)|(?:o|awk)[\s\v&\)<>\|]|pg|r(?:c|ep[\s\v&\)<>\|]|oup(?:[\s\v&\)<>\|]|mod))|tester|unzip|z(?:cat|exe|ip))|h(?:(?:d|up|ash|i(?:ghlight|story))[\s\v&\)<>\|]|e(?:ad[\s\v&\)<>\|]|xdump)|ost(?:id|name)|ping3|t(?:digest|op|passwd))|i(?:d|p(?:6?tables|config)?|rb|conv|f(?:config|top)|nstall[\s\v&\)<>\|]|onice|spell)|j(?:js|q|ava[\s\v&\)<>\|]|exec|o(?:(?:bs|in)[\s\v&\)<>\|]|urnalctl)|runscript)|k(?:s(?:h|shell)|ill(?:[\s\v&\)<>\|]|all)|nife[\s\v&\)<>\|])|l(?:d(?:d?[\s\v&\)<>\|]|config)|(?:[np]|inks|ynx)[\s\v&\)<>\|]|s(?:-F|b_release|cpu|hw|mod|of|pci|usb)?|ua(?:[\s\v&\)<>\|]|(?:la)?tex)|z(?:[\s\v&\)4<>\|]|4c(?:at)?|c(?:at|mp)|diff|[e-f]?grep|less|m(?:a(?:dec|info)?|ore))|a(?:st(?:[\s\v&\)<>\|]|comm|log(?:in)?)|tex[\s\v&\)<>\|])|ess(?:[\s\v&\)<>\|]|echo|(?:fil|pip)e)|ftp(?:get)?|o(?:(?:ca(?:l|te)|ok)[\s\v&\)<>\|]|g(?:inctl|(?:nam|sav)e)|setup)|trace|wp-(?:d(?:ownload|ump)|mirror|request))|m(?:a(?:(?:n|ke)[\s\v&\)<>\|]|il(?:[\s\v&\)<>q\|]|x[\s\v&\)<>\|])|ster\.passwd|wk)|tr|(?:v|utt)[\s\v&\)<>\|]|k(?:dir[\s\v&\)<>\|]|fifo|nod|temp)|locate|o(?:(?:re|unt)[\s\v&\)<>\|]|squitto)|sg(?:attrib|c(?:at|onv)|filter|merge|uniq)|ysql(?:admin|dump(?:slow)?|hotcopy|show)?)|n(?:c(?:[\s\v&\)<>\|]|\.(?:openbsd|traditional)|at)|e(?:t(?:[\s\v&\)<>\|]|(?:c|st)at|kit-ftp|plan)|ofetch)|(?:(?:ul)?l|ice)[\s\v&\)<>\|]|m(?:[\s\v&\)<>\|]|ap)|p(?:m[\s\v&\)<>\|]|ing)|a(?:no[\s\v&\)<>\|]|sm|wk)|o(?:de[\s\v&\)<>\|]|hup)|roff|s(?:enter|lookup|tat))|o(?:(?:d|ctave)[\s\v&\)<>\|]|nintr|p(?:en(?:ssl|v(?:pn|t))|kg))|p(?:a(?:(?:x|rted|tch)[\s\v&\)<>\|]|s(?:swd|te[\s\v&\)<>\|]))|d(?:b|f(?:la)?tex|ksh)|f(?:[\s\v&\)<>\|]|tp)|g(?:rep)?|hp(?:[\s\v&\)57<>\|]|-cgi)|i(?:(?:co?|ng)[\s\v&\)<>\|]|p[^\s\v]|dstat|gz)|k(?:g(?:_?info)?|exec|ill)|r(?:y?[\s\v&\)<>\|]|int(?:env|f[\s\v&\)<>\|]))|t(?:x|ar(?:diff|grep)?)|wd(?:\.db)?|xz|er(?:f|l(?:5|sh)?|ms[\s\v&\)<>\|])|opd|s(?:ed|ftp|ql)|u(?:ppet[\s\v&\)<>\|]|shd)|y(?:thon[^\s\v]|3?versions))|r(?:a(?:r[\s\v&\)<>\|]|k(?:e[\s\v&\)<>\|]|u))|c(?:p[\s\v&\)<>\|])?|e(?:(?:d(?:carpet)?|v|name|p(?:eat|lace))[\s\v&\)<>\|]|a(?:delf|lpath)|stic)|m(?:(?:dir)?[\s\v&\)<>\|]|user)|pm(?:[\s\v&\)<>\|]|db|(?:quer|verif)y)|bash|l(?:ogin|wrap)|nano|oute[\s\v&\)<>\|]|sync|u(?:by[^\s\v]|n-(?:mailcap|parts))|vi(?:ew|m))|s(?:c(?:p|hed|r(?:een|ipt)[\s\v&\)<>\|])|e(?:(?:d|lf|rvice)[\s\v&\)<>\|]|t(?:(?:facl)?[\s\v&\)<>\|]|arch|env|sid)|ndmail)|(?:g|ash|nap)[\s\v&\)<>\|]|h(?:(?:adow|ells)?[\s\v&\)<>\|]|\.distrib|u(?:f|tdown[\s\v&\)<>\|]))|s(?:[\s\v&\)<>\|]|h(?:[\s\v&\)<>\|]|-key(?:ge|sca)n|pass))|u(?:[\s\v&\)<>\|]|do)|vn|diff|ftp|l(?:eep[\s\v&\)<>\|]|sh)|mbclient|o(?:cat|elim|(?:rt|urce)[\s\v&\)<>\|])|p(?:lit[\s\v&\)<>\|]|wd\.db)|qlite3|t(?:art-stop-daemon|d(?:buf|err|in|out)|r(?:ace|ings[\s\v&\)<>\|]))|ys(?:ctl|tem(?:ctl|d-resolve)))|t(?:a(?:c|r[\s\v&\)<>\|]|il[\s\v&\)<>f\|]|sk(?:[\s\v&\)<>\|]|set))|bl|c(?:p(?:[\s\v&\)<>\|]|dump|ing|traceroute)|l?sh)|e(?:[ex][\s\v&\)<>\|]|lnet)|i(?:c[\s\v&\)<>\|]|me(?:(?:out)?[\s\v&\)<>\|]|datectl))|o(?:p|uch[\s\v&\)<>\|])|ftp|mux|r(?:aceroute6?|off)|shark)|u(?:dp|l(?:imit)?[\s\v&\)<>\|]|n(?:ame|(?:compress|s(?:et|hare))[\s\v&\)<>\|]|expand|iq|l(?:ink[\s\v&\)<>\|]|z(?:4|ma))|(?:pig|x)z|rar|z(?:ip[\s\v&\)<>\|]|std))|pdate-alternatives|ser(?:(?:ad|mo)d|del)|u(?:de|en)code)|v(?:i(?:m(?:[\s\v&\)<>\|]|diff)|ew[\s\v&\)<>\|]|gr|pw|rsh)|algrind|olatility[\s\v&\)<>\|])|w(?:3m|c|a(?:ll|tch)[\s\v&\)<>\|]|get|h(?:iptail[\s\v&\)<>\|]|o(?:ami|is))|i(?:reshark|sh[\s\v&\)<>\|]))|x(?:(?:x|pa)d|z(?:[\s\v&\)<>\|]|c(?:at|mp)|d(?:ec|iff)|[e-f]?grep|less|more)|args|e(?:la)?tex|mo(?:dmap|re)|term)|y(?:(?:e(?:s|lp)|arn)[\s\v&\)<>\|]|um)|z(?:ip(?:[\s\v&\)<>\|]|c(?:loak|mp)|details|grep|info|(?:merg|not)e|split|tool)|s(?:h|oelim|td(?:(?:ca|m)t|grep|less)?)|athura|c(?:at|mp)|diff|e(?:grep|ro[\s\v&\)<>\|])|f?grep|less|more|run|ypper))"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1510
        // index 21
        Rule {
            id: 932232,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix Command Injection".to_string(),
            re: r#"(?:t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|[\n\r;`\{]|\|\|?|&&?|\$(?:\(\(?|\{)|[<>]\(|\([\s\v]*\))[\s\v]*(?:[\$\{]|(?:[\s\v]*\(|!)[\s\v]*|[0-9A-Z_a-z]+=(?:[^\s\v]*|\$(?:.*|.*)|[<>].*|'.*'|".*")[\s\v]+)*[\s\v]*["']*(?:["'-\+\--9\?A-\]_a-z\|]+/)?["'\x5c]*(?:(?:(?:a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d|u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?2["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?t)["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|v["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i)["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[\s\v&\),<>\|].*|d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?n["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?f|p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?c["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?n["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[\s\v&\),<>\|].*|s)|w["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:h["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?o|[\s\v&\),<>\|].*))\b"#.to_string()
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1567
        // index 22
        Rule {
            id: 932238,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix Shell Code Found".to_string(),
            re: r#"(?i)(?:(?:^|=)[\s\v]*(?:t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|[\$\{]|(?:[\s\v]*\(|!)[\s\v]*|[0-9A-Z_a-z]+=(?:[^\s\v]*|\$(?:.*|.*)|[<>].*|'.*'|".*")[\s\v]+)*|(?:t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|[\n\r;`\{]|\|\|?|&&?|\$(?:\(\(?|\{)|[<>]\(|\([\s\v]*\))[\s\v]*(?:[\$\{]|(?:[\s\v]*\(|!)[\s\v]*|[0-9A-Z_a-z]+=(?:[^\s\v]*|\$(?:.*|.*)|[<>].*|'.*'|".*")[\s\v]+)*)[\s\v]*["']*(?:["'-\+\--9\?A-\]_a-z\|]+/)?["'\x5c]*(?:(?:(?:a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?t["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d|u["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?2["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?t)["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?e|v["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?i)["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[\s\v&\),<>\|].*|d["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?n["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?f|p["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?c["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?m["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?a["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?n["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?[\s\v&\),<>\|].*|s)|w["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?(?:h["'\)\[-\x5c]*(?:(?:(?:\|\||&&)[\s\v]*)?\$[!#\(\*\-0-9\?-@_a-\{]*)?\x5c?o|[\s\v&\),<>\|].*))"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1660
        // index 23
        Rule {
            id: 932190,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Wildcard bypass technique attempt".to_string(),
            re: r#"/(?:[?*]+[a-z/]+|[a-z/]+[?*]+)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1696
        // index 24
        Rule {
            id: 932301,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: SMTP Command Execution".to_string(),
            re: r#"\r\n(?s:.)*?\b(?:DATA|QUIT|HELP(?: .{1,255})?)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1729
        // index 25
        Rule {
            id: 932311,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: IMAP Command Execution".to_string(),
            re: r#"(?is)\r\n[0-9A-Z_a-z]{1,50}\b (?:C(?:(?:REATE|OPY [\*,0-:]+) ["-#%-&\*\--9A-Z\x5c_a-z]+|APABILITY|HECK|LOSE)|DELETE ["-#%-&\*\--\.0-9A-Z\x5c_a-z]+|EX(?:AMINE ["-#%-&\*\--\.0-9A-Z\x5c_a-z]+|PUNGE)|FETCH [\*,0-:]+|L(?:IST ["-#\*\--9A-Z\x5c_a-z~]+? ["-#%-&\*\--9A-Z\x5c_a-z]+|OG(?:IN [\--\.0-9@_a-z]{1,40} .*?|OUT))|RENAME ["-#%-&\*\--9A-Z\x5c_a-z]+? ["-#%-&\*\--9A-Z\x5c_a-z]+|S(?:E(?:LECT ["-#%-&\*\--9A-Z\x5c_a-z]+|ARCH(?: CHARSET [\--\.0-9A-Z_a-z]{1,40})? (?:(KEYWORD \x5c)?(?:A(?:LL|NSWERED)|BCC|D(?:ELETED|RAFT)|(?:FLAGGE|OL)D|RECENT|SEEN|UN(?:(?:ANSWER|FLAGG)ED|D(?:ELETED|RAFT)|SEEN)|NEW)|(?:BODY|CC|FROM|HEADER .{1,100}|NOT|OR .{1,255}|T(?:EXT|O)) .{1,255}|LARGER [0-9]{1,20}|[\*,0-:]+|(?:BEFORE|ON|S(?:ENT(?:(?:BEFOR|SINC)E|ON)|INCE)) "?[0-9]{1,2}-[0-9A-Z_a-z]{3}-[0-9]{4}"?|S(?:MALLER [0-9]{1,20}|UBJECT .{1,255})|U(?:ID [\*,0-:]+?|NKEYWORD \x5c(Seen|(?:Answer|Flagg)ed|D(?:eleted|raft)|Recent))))|T(?:ORE [\*,0-:]+? [\+\-]?FLAGS(?:\.SILENT)? (?:\(\x5c[a-z]{1,20}\))?|ARTTLS)|UBSCRIBE ["-#%-&\*\--9A-Z\x5c_a-z]+)|UN(?:SUBSCRIBE ["-#%-&\*\--9A-Z\x5c_a-z]+|AUTHENTICATE)|NOOP)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1762
        // index 26
        Rule {
            id: 932321,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: POP3 Command Execution".to_string(),
            re: r#"\r\n(?s:.)*?\b(?:(?:QUI|STA|RSE)(?i:T)|NOOP|CAPA)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf#L1794
        // index 27
        Rule {
            id: 932331,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Remote Command Execution: Unix shell history invocation".to_string(),
            re: r#"!(?:\d|!)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf#L52
        // index 28
        Rule {
            id: 934100,
            class: "DESERIAL".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Node.js Injection Attack 1/2".to_string(),
            re: r#"_(?:\$\$ND_FUNC\$\$_|_js_function)|(?:\beval|new[\s\v]+Function[\s\v]*)\(|String\.fromCharCode|function\(\)\{|this\.constructor|module\.exports=|\([\s\v]*[^0-9A-Z_a-z]child_process[^0-9A-Z_a-z][\s\v]*\)|process(?:\.(?:(?:a(?:ccess|ppendfile|rgv|vailability)|c(?:aveats|h(?:mod|own)|(?:los|opyfil)e|p|reate(?:read|write)stream)|ex(?:ec(?:file)?|ists)|f(?:ch(?:mod|own)|data(?:sync)?|s(?:tat|ync)|utimes)|inodes|l(?:chmod|ink|stat|utimes)|mkd(?:ir|temp)|open(?:dir)?|r(?:e(?:ad(?:dir|file|link|v)?|name)|m)|s(?:pawn(?:file)?|tat|ymlink)|truncate|u(?:n(?:link|watchfile)|times)|w(?:atchfile|rite(?:file|v)?))(?:sync)?(?:\.call)?\(|binding|constructor|env|global|main(?:Module)?|process|require)|\[["'`](?:(?:a(?:ccess|ppendfile|rgv|vailability)|c(?:aveats|h(?:mod|own)|(?:los|opyfil)e|p|reate(?:read|write)stream)|ex(?:ec(?:file)?|ists)|f(?:ch(?:mod|own)|data(?:sync)?|s(?:tat|ync)|utimes)|inodes|l(?:chmod|ink|stat|utimes)|mkd(?:ir|temp)|open(?:dir)?|r(?:e(?:ad(?:dir|file|link|v)?|name)|m)|s(?:pawn(?:file)?|tat|ymlink)|truncate|u(?:n(?:link|watchfile)|times)|w(?:atchfile|rite(?:file|v)?))(?:sync)?|binding|constructor|env|global|main(?:Module)?|process|require)["'`]\])|(?:binding|constructor|env|global|main(?:Module)?|process|require)\[|console(?:\.(?:debug|error|info|trace|warn)(?:\.call)?\(|\[["'`](?:debug|error|info|trace|warn)["'`]\])|require(?:\.(?:resolve(?:\.call)?\(|main|extensions|cache)|\[["'`](?:(?:resolv|cach)e|main|extensions)["'`]\])"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf#L122
        // index 29
        Rule {
            id: 934130,
            class: "PP".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "JavaScript Prototype Pollution".to_string(),
            re: r#"(?:__proto__|constructor\s*(?:\.|\[)\s*prototype)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf#L154
        // index 30
        Rule {
            id: 934150,
            class: "RCE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Ruby Injection Attack".to_string(),
            re: r#"Process[\s\v]*\.[\s\v]*spawn[\s\v]*\("#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf#L185
        // index 31
        Rule {
            id: 934160,
            class: "DOS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Node.js DoS attack".to_string(),
            re: r#"while[\s\v]*\([\s\v\(]*(?:!+(?:false|null|undefined|NaN|[\+\-]?0|"{2}|'{2}|`{2})|(?:!!)*(?:(?:t(?:rue|his)|[\+\-]?(?:Infinity|[1-9][0-9]*)|new [A-Za-z][0-9A-Z_a-z]*|window|String|(?:Boolea|Functio)n|Object|Array)\b|\{.*\}|\[.*\]|"[^"]+"|'[^']+'|`[^`]+`)).*\)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf#L243
        // index 32
        Rule {
            id: 934101,
            class: "DESERIAL".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Node.js Injection Attack 2/2".to_string(),
            re: r#"(?:close|exists|fork|(?:ope|spaw)n|re(?:ad|quire)|w(?:atch|rite))[\s\v]*\("#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf#L296
        // index 33
        Rule {
            id: 934120,
            class: "SSRF".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Possible Server Side Request Forgery (SSRF) Attack: URL Parameter using IP Address".to_string(),
            re: r#"(?i)((?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://(?:[0-9]{10}|(?:0x[0-9a-f]{2}\.){3}0x[0-9a-f]{2}|0x(?:[0-9a-f]{8}|[0-9a-f]{16})|(?:0{1,4}[0-9]{1,3}\.){3}0{1,4}[0-9]{1,3}|[0-9]{1,3}\.(?:[0-9]{1,3}\.[0-9]{5}|[0-9]{8})|(?:\x5c\x5c[\-0-9a-z]\.?_?)+|\[[0-:a-f]+(?:[\.0-9]+|%[0-9A-Z_a-z]+)?\]|[a-z][\--\.0-9A-Z_a-z]{1,255}:[0-9]{1,5}(?:#?[\s\v]*&?@(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-z][\--\.0-9A-Z_a-z]{1,255}):[0-9]{1,5}/?)+|[\.0-9]{0,11}(?:\xe2(?:\x91[\xa0-\xbf]|\x92[\x80-\xbf]|\x93[\x80-\xa9\xab-\xbf])|\xe3\x80\x82)+))"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L106
        // index 34
        Rule {
            id: 941110,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "XSS Filter - Category 1: Script Tag Vector".to_string(),
            re: r#"(?i)<script[^>]*>[\s\S]*?"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L136
        // index 35
        Rule {
            id: 941130,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "XSS Filter - Category 3: Attribute Vector".to_string(),
            re: r#"(?i).(?:\b(?:x(?:link:href|html|mlns)|data:text/html|formaction|pattern\b.*?=)|!ENTITY[\s\v]+(?:%[\s\v]+)?[^\s\v]+[\s\v]+(?:SYSTEM|PUBLIC)|@import|;base64)\b"#.to_string()
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L165
        // index 36
        Rule {
            id: 941140,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "XSS Filter - Category 4: Javascript URI Vector".to_string(),
            re: r#"(?i)[a-z]+=(?:[^:=]+:.+;)*?[^:=]+:url\(javascript"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L198
        // index 37
        Rule {
            id: 941160,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "NoScript XSS InjectionChecker: HTML Injection".to_string(),
            re: r#"(?i)<[^0-9<>A-Z_a-z]*(?:[^\s\v"'<>]*:)?[^0-9<>A-Z_a-z]*[^0-9A-Z_a-z]*?(?:s[^0-9A-Z_a-z]*?(?:c[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?p[^0-9A-Z_a-z]*?t|t[^0-9A-Z_a-z]*?y[^0-9A-Z_a-z]*?l[^0-9A-Z_a-z]*?e|v[^0-9A-Z_a-z]*?g|e[^0-9A-Z_a-z]*?t[^0-9>A-Z_a-z])|f[^0-9A-Z_a-z]*?o[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?m|m[^0-9A-Z_a-z]*?(?:a[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?q[^0-9A-Z_a-z]*?u[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?e|e[^0-9A-Z_a-z]*?t[^0-9A-Z_a-z]*?a[^0-9>A-Z_a-z])|(?:l[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?n[^0-9A-Z_a-z]*?k|o[^0-9A-Z_a-z]*?b[^0-9A-Z_a-z]*?j[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?c[^0-9A-Z_a-z]*?t|e[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?b[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?d|a[^0-9A-Z_a-z]*?(?:p[^0-9A-Z_a-z]*?p[^0-9A-Z_a-z]*?l[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?t|u[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?o|n[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?t[^0-9A-Z_a-z]*?e)|p[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?m|i?[^0-9A-Z_a-z]*?f[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?e|b[^0-9A-Z_a-z]*?(?:a[^0-9A-Z_a-z]*?s[^0-9A-Z_a-z]*?e|o[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?y|i[^0-9A-Z_a-z]*?n[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?n[^0-9A-Z_a-z]*?g[^0-9A-Z_a-z]*?s)|i[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?a?[^0-9A-Z_a-z]*?g[^0-9A-Z_a-z]*?e?|v[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?o)[^0-9>A-Z_a-z])|(?:<[0-9A-Z_a-z].*[\s\v/]|["'](?:.*[\s\v/])?)(?:background|formaction|lowsrc|on(?:a(?:bort|ctivate|d(?:apteradded|dtrack)|fter(?:print|(?:scriptexecu|upda)te)|lerting|n(?:imation(?:cancel|end|iteration|start)|tennastatechange)|ppcommand|u(?:dio(?:end|process|start)|xclick))|b(?:e(?:fore(?:(?:(?:(?:de)?activa|scriptexecu)t|toggl)e|c(?:opy|ut)|editfocus|input|p(?:aste|rint)|u(?:nload|pdate))|gin(?:Event)?)|l(?:ocked|ur)|oun(?:ce|dary)|roadcast|usy)|c(?:a(?:(?:ch|llschang)ed|nplay(?:through)?|rdstatechange)|(?:ell|fstate)change|h(?:a(?:rging(?:time)?cha)?nge|ecking)|l(?:ick|ose)|o(?:m(?:mand(?:update)?|p(?:lete|osition(?:end|start|update)))|n(?:nect(?:ed|ing)|t(?:extmenu|rolselect))|py)|u(?:echange|t))|d(?:ata(?:(?:availabl|chang)e|error|setc(?:hanged|omplete))|blclick|e(?:activate|livery(?:error|success)|vice(?:found|light|(?:mo|orienta)tion|proximity))|i(?:aling|s(?:abled|c(?:hargingtimechange|onnect(?:ed|ing))))|o(?:m(?:a(?:ctivate|ttrmodified)|(?:characterdata|subtree)modified|focus(?:in|out)|mousescroll|node(?:inserted(?:intodocument)?|removed(?:fromdocument)?))|wnloading)|r(?:ag(?:drop|e(?:n(?:d|ter)|xit)|(?:gestur|leav)e|over|start)|op)|urationchange)|e(?:mptied|n(?:abled|d(?:ed|Event)?|ter)|rror(?:update)?|xit)|f(?:ailed|i(?:lterchange|nish)|o(?:cus(?:in|out)?|rm(?:change|input))|ullscreenchange)|g(?:amepad(?:axismove|button(?:down|up)|(?:dis)?connected)|et)|h(?:ashchange|e(?:adphoneschange|l[dp])|olding)|i(?:cc(?:cardlockerror|infochange)|n(?:coming|put|valid))|key(?:down|press|up)|l(?:evelchange|o(?:ad(?:e(?:d(?:meta)?data|nd)|start)?|secapture)|y)|m(?:ark|essage|o(?:use(?:down|enter|(?:lea|mo)ve|o(?:ut|ver)|up|wheel)|ve(?:end|start)?|z(?:a(?:fterpaint|udioavailable)|(?:beforeresiz|orientationchang|t(?:apgestur|imechang))e|(?:edgeui(?:c(?:ancel|omplet)|start)e|network(?:down|up)loa)d|fullscreen(?:change|error)|m(?:agnifygesture(?:start|update)?|ouse(?:hittest|pixelscroll))|p(?:ointerlock(?:change|error)|resstapgesture)|rotategesture(?:start|update)?|s(?:crolledareachanged|wipegesture(?:end|start|update)?))))|no(?:match|update)|o(?:(?:bsolet|(?:ff|n)lin)e|pen|verflow(?:changed)?)|p(?:a(?:ge(?:hide|show)|int|(?:st|us)e)|lay(?:ing)?|o(?:inter(?:down|enter|(?:(?:lea|mo)v|rawupdat)e|o(?:ut|ver)|up)|p(?:state|up(?:hid(?:den|ing)|show(?:ing|n))))|ro(?:gress|pertychange))|r(?:atechange|e(?:adystatechange|ceived|movetrack|peat(?:Event)?|quest|s(?:et|ize|u(?:lt|m(?:e|ing)))|trieving)|ow(?:e(?:nter|xit)|s(?:delete|inserted)))|s(?:croll(?:end)?|e(?:arch|ek(?:complete|ed|ing)|lect(?:ionchange|start)?|n(?:ding|t)|t)|how|(?:ound|peech)(?:end|start)|t(?:a(?:lled|rt|t(?:echange|uschanged))|k(?:comma|sessione)nd|op)|u(?:bmit|ccess|spend)|vg(?:abort|error|(?:un)?load|resize|scroll|zoom))|t(?:ext|ime(?:out|update)|o(?:ggle|uch(?:cancel|en(?:d|ter)|(?:lea|mo)ve|start))|ransition(?:cancel|end|run|start))|u(?:n(?:derflow|handledrejection|load)|p(?:dateready|gradeneeded)|s(?:erproximity|sdreceived))|v(?:ersion|o(?:ic|lum)e)change|w(?:a(?:it|rn)ing|ebkit(?:animation(?:end|iteration|start)|transitionend)|heel)|zoom)|ping|s(?:rc|tyle))[\x08-\n\f-\r ]*?="#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L223
        // index XX
        // 500ms to run!
        /*
        Rule {
            id: 941170,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "NoScript XSS InjectionChecker: Attribute Injection".to_string(),
            re: r#"(?i)(?:\W|^)(?:javascript:(?:[\s\S]+[=\x5c\(\[\.<]|[\s\S]*?(?:\bname\b|\x5c[ux]\d))|data:(?:(?:[a-z]\w+/\w[\w+-]+\w)?[;,]|[\s\S]*?;[\s\S]*?\b(?:base64|charset=)|[\s\S]*?,[\s\S]*?<[\s\S]*?\w[\s\S]*?>))|@\W*?i\W*?m\W*?p\W*?o\W*?r\W*?t\W*?(?:/\*[\s\S]*?)?(?:["']|\W*?u\W*?r\W*?l[\s\S]*?\()|[^-]*?-\W*?m\W*?o\W*?z\W*?-\W*?b\W*?i\W*?n\W*?d\W*?i\W*?n\W*?g[^:]*?:\W*?u\W*?r\W*?l[\s\S]*?\("#.to_string(),
        },
        */

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L579
        // index 38
        Rule {
            id: 941310,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "US-ASCII Malformed Encoding XSS Filter - Attack Detected".to_string(),
            re: r#"\xbc[^\xbe>]*[\xbe>]|<[^\xbe]*\xbe"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L609
        // index 39
        Rule {
            id: 941350,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "UTF-7 Encoding IE XSS - Attack Detected".to_string(),
            re: r#"\+ADw-.*(?:\+AD4-|>)|<.*\+AD4-"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L652
        // index 40
        Rule {
            id: 941360,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "JSFuck / Hieroglyphy obfuscation detected".to_string(),
            re: r#"![!+ ]\[\]"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L680
        // index 41
        Rule {
            id: 941370,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "JavaScript global variable found".to_string(),
            re: r#"(?:self|document|this|top|window)\s*(?:/\*|[\[)]).+?(?:\]|\*/)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L712
        // index 42
        Rule {
            id: 941390,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Javascript method detected".to_string(),
            re: r#"(?i)\b(?:eval|set(?:timeout|interval)|new[\s\v]+Function|a(?:lert|tob)|btoa|prompt|confirm)[\s\v]*\("#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L742
        // index 43
        Rule {
            id: 941400,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "XSS JavaScript function without parentheses".to_string(),
            re: r#"((?:\[[^\]]*\][^.]*\.)|Reflect[^.]*\.).*(?:map|sort|apply)[^.]*\..*call[^`]*`.*`"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L806
        // index 44
        Rule {
            id: 941120,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "XSS Filter - Category 2: Event Handler Vector".to_string(),
            re: r#"(?i)[\s"'`;/0-9=\x0B\x09\x0C\x3B\x2C\x28\x3B]on[a-zA-Z]{3,25}[\s\x0B\x09\x0C\x3B\x2C\x28\x3B]*?=[^=]"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L832C144-L832C182
        // index 45
        Rule {
            id: 941150,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "XSS Filter - Category 5: Disallowed HTML Attributes".to_string(),
            re: r#"(?i)\b(?:s(?:tyle|rc)|href)\b[\s\S]*?="#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L947
        // index 46
        Rule {
            id: 941320,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Possible XSS Attack Detected - HTML Tag Handler".to_string(),
            re: r#"<(?:a|abbr|acronym|address|applet|area|audioscope|b|base|basefront|bdo|bgsound|big|blackface|blink|blockquote|body|bq|br|button|caption|center|cite|code|col|colgroup|comment|dd|del|dfn|dir|div|dl|dt|em|embed|fieldset|fn|font|form|frame|frameset|h1|head|hr|html|i|iframe|ilayer|img|input|ins|isindex|kdb|keygen|label|layer|legend|li|limittext|link|listing|map|marquee|menu|meta|multicol|nobr|noembed|noframes|noscript|nosmartquotes|object|ol|optgroup|option|p|param|plaintext|pre|q|rt|ruby|s|samp|script|select|server|shadow|sidebar|small|spacer|span|strike|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|title|tr|tt|u|ul|var|wbr|xml|xmp)\W"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L969
        // index 47
        Rule {
            id: 941330,
            class: "XSS".to_string(),
            severity: "CRTICIAL".to_string(),
            desc: "IE XSS Filters - Attack Detected".to_string(),
            re: r#"(?i:["'][ ]*(?:[^a-z0-9~_:' ]|in).*?(?:(?:l|\x5cu006C)(?:o|\x5cu006F)(?:c|\x5cu0063)(?:a|\x5cu0061)(?:t|\x5cu0074)(?:i|\x5cu0069)(?:o|\x5cu006F)(?:n|\x5cu006E)|(?:n|\x5cu006E)(?:a|\x5cu0061)(?:m|\x5cu006D)(?:e|\x5cu0065)|(?:o|\x5cu006F)(?:n|\x5cu006E)(?:e|\x5cu0065)(?:r|\x5cu0072)(?:r|\x5cu0072)(?:o|\x5cu006F)(?:r|\x5cu0072)|(?:v|\x5cu0076)(?:a|\x5cu0061)(?:l|\x5cu006C)(?:u|\x5cu0075)(?:e|\x5cu0065)(?:O|\x5cu004F)(?:f|\x5cu0066)).*?=)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L994
        // index 48
        Rule {
            id: 941340,
            class: "XSS".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "IE XSS Filters - Attack Detected".to_string(),
            re: r#"(?i)["'][ ]*(?:[^a-z0-9~_:' ]|in).+?[.].+?="#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L1029
        // index 49
        Rule {
            id: 941380,
            class: "TEMPLATE".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "AngularJS client side template injection detected".to_string(),
            re: r#"\{\{.*?}}"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L77
        // index 50
        Rule {
            id: 942140,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "SQL Injection Attack: Common DB Names Detected".to_string(),
            re: r#"(?i)\b(?:d(?:atabas|b_nam)e[^0-9A-Z_a-z]*\(|(?:information_schema|m(?:aster\.\.sysdatabases|s(?:db|ys(?:ac(?:cess(?:objects|storage|xml)|es)|modules2?|(?:object|querie|relationship)s))|ysql\.db)|northwind|pg_(?:catalog|toast)|tempdb)\b|s(?:chema(?:_name\b|[^0-9A-Z_a-z]*\()|(?:qlite_(?:temp_)?master|ys(?:aux|\.database_name))\b))"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L110
        // index 51
        Rule {
            id: 942151,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "SQL Injection Attack: SQL function name detected".to_string(),
            re: r#"(?i)\b(?:a(?:dd(?:dat|tim)e|es_(?:de|en)crypt|s(?:cii(?:str)?|in)|tan2?)|b(?:enchmark|i(?:n_to_num|t_(?:and|count|length|x?or)))|c(?:har(?:acter)?_length|iel(?:ing)?|o(?:alesce|ercibility|llation|(?:mpres)?s|n(?:cat(?:_ws)?|nection_id|v(?:ert(?:_tz)?)?)|t)|r32|ur(?:(?:dat|tim)e|rent_(?:date|setting|time(?:stamp)?|user)))|d(?:a(?:t(?:abase(?:_to_xml)?|e(?:_(?:add|format|sub)|diff))|y(?:name|of(?:month|week|year)))|count|e(?:code|grees|s_(?:de|en)crypt)|ump)|e(?:lt|n(?:c(?:ode|rypt)|ds_?with)|x(?:p(?:ort_set)?|tract(?:value)?))|f(?:i(?:el|n)d_in_set|ound_rows|rom_(?:base64|days|unixtime))|g(?:e(?:ometrycollection|t(?:_(?:format|lock)|pgusername))|(?:r(?:eates|oup_conca)|tid_subse)t)|hex(?:toraw)?|i(?:fnull|n(?:et6?_(?:aton|ntoa)|s(?:ert|tr)|terval)|s(?:_(?:(?:free|used)_lock|ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull)|superuser)|null))|json(?:_(?:a(?:gg|rray(?:_(?:elements(?:_text)?|length))?)|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|object(?:_(?:agg|keys))?|populate_record(?:set)?|strip_nulls|t(?:o_record(?:set)?|ypeof))|b(?:_(?:array(?:_(?:elements(?:_text)?|length))?|build_(?:array|object)|object(?:_(?:agg|keys))?|e(?:ac|xtract_pat)h(?:_text)?|insert|p(?:ath_(?:(?:exists|match)(?:_tz)?|query(?:_(?:(?:array|first)(?:_tz)?|tz))?)|opulate_record(?:set)?|retty)|s(?:et(?:_lax)?|trip_nulls)|t(?:o_record(?:set)?|ypeof)))?|path)?|l(?:ast_(?:day|inser_id)|case|e(?:as|f)t|i(?:kel(?:ihood|y)|nestring)|o(?:_(?:from_bytea|put)|ad_file|ca(?:ltimestamp|te)|g(?:10|2)|wer)|pad|trim)|m(?:a(?:ke(?:_set|date)|ster_pos_wait)|d5|i(?:crosecon)?d|onthname|ulti(?:linestring|po(?:int|lygon)))|n(?:ame_const|ot_in|ullif)|o(?:ct(?:et_length)?|(?:ld_passwo)?rd)|p(?:eriod_(?:add|diff)|g_(?:client_encoding|(?:databas|read_fil)e|l(?:argeobject|s_dir)|sleep|user)|o(?:(?:lyg|siti)on|w)|rocedure_analyse)|qu(?:arter|ery_to_xml|ote)|r(?:a(?:dians|nd|wtohex)|elease_lock|ow_(?:count|to_json)|pad|trim)|s(?:chema|e(?:c_to_time|ssion_user)|ha[1-2]?|in|oundex|pace|q(?:lite_(?:compileoption_(?:get|used)|source_id)|rt)|t(?:arts_?with|d(?:dev_(?:po|sam)p)?|r(?:_to_date|cmp))|ub(?:(?:dat|tim)e|str(?:ing(?:_index)?)?)|ys(?:date|tem_user))|t(?:ime(?:_(?:format|to_sec)|diff|stamp(?:add|diff)?)|o(?:_(?:base64|jsonb?)|n?char|(?:day|second)s)|r(?:im|uncate))|u(?:case|n(?:compress(?:ed_length)?|hex|i(?:str|x_timestamp)|likely)|(?:pdatexm|se_json_nul)l|tc_(?:date|time(?:stamp)?)|uid(?:_short)?)|var(?:_(?:po|sam)p|iance)|we(?:ek(?:day|ofyear)|ight_string)|xmltype|yearweek)[^0-9A-Z_a-z]*\("#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L179
        // index 52
        Rule {
            id: 942170,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Detects SQL benchmark and sleep injection attempts including conditional queries".to_string(),
            re: r#"(?i)(?:select|;)[\s\v]+(?:benchmark|if|sleep)[\s\v]*?\([\s\v]*?\(?[\s\v]*?[0-9A-Z_a-z]+"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L205
        // index 53
        Rule {
            id: 942190,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Detects MSSQL code execution and information gathering attempts".to_string(),
            re: r#"(?i)["'`](?:[\s\v]*![\s\v]*["'0-9A-Z_-z]|;?[\s\v]*(?:having|select|union\b[\s\v]*(?:all|(?:distin|sele)ct))\b[\s\v]*[^\s\v])|\b(?:(?:(?:c(?:onnection_id|urrent_user)|database|schema|user)[\s\v]*?|select.*?[0-9A-Z_a-z]?user)\(|exec(?:ute)?[\s\v]+master\.|from[^0-9A-Z_a-z]+information_schema[^0-9A-Z_a-z]|into[\s\v\+]+(?:dump|out)file[\s\v]*?["'`]|union(?:[\s\v]select[\s\v]@|[\s\v\(0-9A-Z_a-z]*?select))|[\s\v]*?exec(?:ute)?.*?[^0-9A-Z_a-z]xp_cmdshell|[^0-9A-Z_a-z]iif[\s\v]*?\("#.to_string()
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L255
        // index 54
        Rule {
            id: 942230,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Detects conditional SQL injection attempts".to_string(),
            re: r#"(?i)[\s\v\(-\)]case[\s\v]+when.*?then|\)[\s\v]*?like[\s\v]*?\(|select.*?having[\s\v]*?[^\s\v]+[\s\v]*?[^\s\v0-9A-Z_a-z]|if[\s\v]?\([0-9A-Z_a-z]+[\s\v]*?[<->~]"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L281
        // index 55
        Rule {
            id: 942240,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Detects MySQL charset switch and MSSQL DoS attempts".to_string(),
            re: r#"(?i)alter[\s\v]*?[0-9A-Z_a-z]+.*?char(?:acter)?[\s\v]+set[\s\v]+[0-9A-Z_a-z]+|["'`](?:;*?[\s\v]*?waitfor[\s\v]+(?:time|delay)[\s\v]+["'`]|;.*?:[\s\v]*?goto)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L302
        // index 56
        Rule {
            id: 942250,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections".to_string(),
            re: r#"(?i:merge.*?using\s*?\(|execute\s*?immediate\s*?["'`]|match\s*?[\w(),+-]+\s*?against\s*?\()"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L323
        // index 57
        Rule {
            id: 942270,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Looking for basic sql injection. Common attack string for mysql, oracle and others".to_string(),
            re: r#"(?i)union.*?select.*?from"#.to_string(),
        }, 

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L349
        // index 58
        Rule {
            id: 942280,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts".to_string(),
            re: r#"(?i)select[\s\v]*?pg_sleep|waitfor[\s\v]*?delay[\s\v]?["'`]+[\s\v]?[0-9]|;[\s\v]*?shutdown[\s\v]*?(?:[#;\{]|/\*|--)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L375
        // index 59
        Rule {
            id: 942290,
            class: "NOSQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Finds basic MongoDB SQL injection attempts".to_string(),
            re: r#"(?i)\[?\$(?:n(?:e|in?|o[rt])|e(?:q|xists|lemMatch)|l(?:te?|ike)|mod|a(?:ll|nd)|(?:s(?:iz|lic)|wher)e|t(?:ype|ext)|x?or|div|between|regex|jsonSchema)\]?"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L404
        // index 60
        Rule {
            id: 942320,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Detects MySQL and PostgreSQL stored procedure/function injections".to_string(),
            re: r#"(?i)create[\s\v]+(?:function|procedure)[\s\v]*?[0-9A-Z_a-z]+[\s\v]*?\([\s\v]*?\)[\s\v]*?-|d(?:eclare[^0-9A-Z_a-z]+[#@][\s\v]*?[0-9A-Z_a-z]+|iv[\s\v]*?\([\+\-]*[\s\v\.0-9]+,[\+\-]*[\s\v\.0-9]+\))|exec[\s\v]*?\([\s\v]*?@|(?:lo_(?:impor|ge)t|procedure[\s\v]+analyse)[\s\v]*?\(|;[\s\v]*?(?:declare|open)[\s\v]+[\-0-9A-Z_a-z]+|::(?:b(?:igint|ool)|double[\s\v]+precision|int(?:eger)?|numeric|oid|real|(?:tex|smallin)t)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L430C1-L430C1
        // index 61
        Rule {
            id: 942350,
            class: "SQLI".to_string(),
            severity: "CRICITAL".to_string(),
            desc: "Detects MySQL UDF injection and other data/structure manipulation attempts".to_string(),
            re: r#"(?i)create[\s\v]+function[\s\v].+[\s\v]returns|;[\s\v]*?(?:alter|(?:(?:cre|trunc|upd)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)\b[\s\v]*?[\(\[]?[0-9A-Z_a-z]{2,}"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L469
        // index 62
        Rule {
            id: 942360,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Detects concatenated basic SQL injection and SQLLFI attempts".to_string(),
            re: r#"(?i)\b(?:(?:alter|(?:(?:cre|trunc|upd)at|renam)e|de(?:lete|sc)|(?:inser|selec)t|load)[\s\v]+(?:char|group_concat|load_file)\b[\s\v]*\(?|end[\s\v]*?\);)|[\s\v\(]load_file[\s\v]*?\(|[\"'`][\s\v]+regexp[^0-9A-Z_a-z]|[\"'0-9A-Z_-z][\s\v]+as\b[\s\v]*[\"'0-9A-Z_-z]+[\s\v]*\bfrom|^[^A-Z_a-z]+[\s\v]*?(?:(?:(?:(?:cre|trunc)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)[\s\v]+[0-9A-Z_a-z]+|u(?:pdate[\s\v]+[0-9A-Z_a-z]+|nion[\s\v]*(?:all|(?:sele|distin)ct)\b)|alter[\s\v]*(?:a(?:(?:ggregat|pplication[\s\v]*rol)e|s(?:sembl|ymmetric[\s\v]*ke)y|u(?:dit|thorization)|vailability[\s\v]*group)|b(?:roker[\s\v]*priority|ufferpool)|c(?:ertificate|luster|o(?:l(?:latio|um)|nversio)n|r(?:edential|yptographic[\s\v]*provider))|d(?:atabase|efault|i(?:mension|skgroup)|omain)|e(?:(?:ndpoi|ve)nt|xte(?:nsion|rnal))|f(?:lashback|oreign|u(?:lltext|nction))|hi(?:erarchy|stogram)|group|in(?:dex(?:type)?|memory|stance)|java|l(?:a(?:ngua|r)ge|ibrary|o(?:ckdown|g(?:file[\s\v]*group|in)))|m(?:a(?:s(?:k|ter[\s\v]*key)|terialized)|e(?:ssage[\s\v]*type|thod)|odule)|(?:nicknam|queu)e|o(?:perator|utline)|p(?:a(?:ckage|rtition)|ermission|ro(?:cedur|fil)e)|r(?:e(?:mot|sourc)e|o(?:l(?:e|lback)|ute))|s(?:chema|e(?:arch|curity|rv(?:er|ice)|quence|ssion)|y(?:mmetric[\s\v]*key|nonym)|togroup)|t(?:able(?:space)?|ext|hreshold|r(?:igger|usted)|ype)|us(?:age|er)|view|w(?:ork(?:load)?|rapper)|x(?:ml[\s\v]*schema|srobject))\b)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L505
        // index 63
        Rule {
            id: 942500,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "MySQL in-line comment detected".to_string(),
            re: r#"(?i:\*[!+](?:[\w\s=_\-()]+)?\*)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L541
        // index 64
        Rule {
            id: 942540,
            class: "SQLI".to_string(),
            severity: "CRTICIAL".to_string(),
            desc: "SQL Authentication bypass (split query)".to_string(),
            re: r#"^(?:[^']*'|[^\"]*\"|[^`]*`)[\s\v]*;"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L571
        // index 65
        Rule {
            id: 942560,
            class: "SQLI".to_string(),
            severity: "CRTICIAL".to_string(),
            desc: "MySQL Scientific Notation payload detected".to_string(),
            re: r#"(?i)1\.e[\(-\),]"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L600
        // index 66
        Rule {
            id: 942550,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "JSON-Based SQL Injection".to_string(),
            re: r#"[\"'`][\[\{].*[\]\}][\"'`].*(::.*jsonb?)?.*(?:(?:@|->?)>|<@|\?[&\|]?|#>>?|[<>]|<-)|(?:(?:@|->?)>|<@|\?[&\|]?|#>>?|[<>]|<-)[\"'`][\[\{].*[\]\}][\"'`]|json_extract.*\(.*\)"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L670
        // index 67
        Rule {
            id: 942120,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "SQL Injection Attack: SQL Operator Detected".to_string(),
            re: r#"(?i)!=|&&|\|\||>[=->]|<(?:<|=>?|>(?:[\s\v]+binary)?)|\b(?:(?:xor|r(?:egexp|like)|i(?:snull|like)|notnull)\b|collate(?:[^0-9A-Z_a-z]*?(?:U&)?["'`]|[^0-9A-Z_a-z]+(?:(?:binary|nocase|rtrim)\b|[0-9A-Z_a-z]*?_))|(?:likel(?:ihood|y)|unlikely)[\s\v]*\()|r(?:egexp|like)[\s\v]+binary|not[\s\v]+between[\s\v]+(?:0[\s\v]+and|(?:'[^']*'|"[^"]*")[\s\v]+and[\s\v]+(?:'[^']*'|"[^"]*"))|is[\s\v]+null|like[\s\v]+(?:null|[0-9A-Z_a-z]+[\s\v]+escape\b)|(?:^|[^0-9A-Z_a-z])in[\s\v\+]*\([\s\v"0-9]+[^\(-\)]*\)|[!<->]{1,2}[\s\v]*all\b"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L711
        // index 68
        Rule {
            id: 942130,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "SQL Injection Attack: SQL Boolean-based attack detected".to_string(),
            re: r#"(?i)[\s\v"'-\)`]*?\b([0-9A-Z_a-z]+)\b[\s\v"'-\)`]*?(?:=|<=>|(?:sounds[\s\v]+)?like|glob|r(?:like|egexp))[\s\v"'-\)`]*?\b([0-9A-Z_a-z]+)\b"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L747
        // index 69
        Rule {
            id: 942131,
            class: "SQLI".to_string(),
            severity: "CRTICIAL".to_string(),
            desc: "SQL Injection Attack: SQL Boolean-based attack detected".to_string(),
            re: r#"(?i)[\s\v"'-\)`]*?\b([0-9A-Z_a-z]+)\b[\s\v"'-\)`]*?(?:![<->]|<[=->]?|>=?|\^|is[\s\v]+not|not[\s\v]+(?:like|r(?:like|egexp)))[\s\v"'-\)`]*?\b([0-9A-Z_a-z]+)\b"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L784
        // index 70
        Rule {
            id: 942150,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "SQL Injection Attack: SQL function name detected".to_string(),
            re: r#"(?i)\b(?:json(?:_[0-9A-Z_a-z]+)?|a(?:bs|(?:cos|sin)h?|tan[2h]?|vg)|c(?:eil(?:ing)?|h(?:a(?:nges|r(?:set)?)|r)|o(?:alesce|sh?|unt)|ast)|d(?:e(?:grees|fault)|a(?:te|y))|exp|f(?:loor(?:avg)?|ormat|ield)|g(?:lob|roup_concat)|h(?:ex|our)|i(?:f(?:null)?|if|n(?:str)?)|l(?:ast(?:_insert_rowid)?|ength|ike(?:l(?:ihood|y))?|n|o(?:ad_extension|g(?:10|2)?|wer(?:pi)?|cal)|trim)|m(?:ax|in(?:ute)?|o(?:d|nth))|n(?:ullif|ow)|p(?:i|ow(?:er)?|rintf|assword)|quote|r(?:a(?:dians|ndom(?:blob)?)|e(?:p(?:lace|eat)|verse)|ound|trim|ight)|s(?:i(?:gn|nh?)|oundex|q(?:lite_(?:compileoption_(?:get|used)|offset|source_id|version)|rt)|u(?:bstr(?:ing)?|m)|econd|leep)|t(?:anh?|otal(?:_changes)?|r(?:im|unc)|ypeof|ime)|u(?:n(?:icode|likely)|(?:pp|s)er)|zeroblob|bin|v(?:alues|ersion)|week|year)[^0-9A-Z_a-z]*\("#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L827
        // index 71
        Rule {
            id: 942180,
            class: "SQLI".to_string(),
            severity: "CRTICIAL".to_string(),
            desc: "Detects basic SQL authentication bypass attempts 1/3".to_string(),
            re: r#"(?i)(?:/\*)+["'`]+[\s\v]?(?:--|[#\{]|/\*)?|["'`](?:[\s\v]*(?:(?:x?or|and|div|like|between)[\s\v\-0-9A-Z_a-z]+[\(-\)\+-\-<->][\s\v]*["'0-9`]|[!=\|](?:[\s\v -!\+\-0-9=]+.*?["'-\(`].*?|[\s\v -!0-9=]+.*?[0-9]+)$|(?:like|print)[^0-9A-Z_a-z]+["'-\(0-9A-Z_-z]|;)|(?:[<>~]+|[\s\v]*[^\s\v0-9A-Z_a-z]?=[\s\v]*|[^0-9A-Z_a-z]*?[\+=]+[^0-9A-Z_a-z]*?)["'`])|[0-9]["'`][\s\v]+["'`][\s\v]+[0-9]|^admin[\s\v]*?["'`]|[\s\v"'-\(`][\s\v]*?glob[^0-9A-Z_a-z]+["'-\(0-9A-Z_-z]|[\s\v]is[\s\v]*?0[^0-9A-Z_a-z]|where[\s\v][\s\v,-\.0-9A-Z_a-z]+[\s\v]="#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L856
        // index 72
        Rule {
            id: 942200,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Detects MySQL comment-/space-obfuscated injections and backtick termination".to_string(),
            re: r#"(?i),.*?["'\)0-9`-f]["'`](?:["'`].*?["'`]|(?:\r?\n)?\z|[^"'`]+)|[^0-9A-Z_a-z]select.+[^0-9A-Z_a-z]*?from|(?:alter|(?:(?:cre|trunc|upd)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)[\s\v]*?\([\s\v]*?space[\s\v]*?\("#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L885
        // index 73
        Rule {
            id: 942210,
            class: "SQLI".to_string(),
            severity: "CRTICIAL".to_string(),
            desc: "Detects chained SQL injection attempts 1/2".to_string(),
            re: r#"(?i)(?:&&|\|\||and|between|div|like|n(?:and|ot)|(?:xx?)?or)[\s\v\(]+[0-9A-Z_a-z]+[\s\v\)]*?[!\+=]+[\s\v0-9]*?["'-\)=`]|[0-9](?:[\s\v]*?(?:and|between|div|like|x?or)[\s\v]*?[0-9]+[\s\v]*?[\+\-]|[\s\v]+group[\s\v]+by.+\()|/[0-9A-Z_a-z]+;?[\s\v]+(?:and|between|div|having|like|x?or|select)[^0-9A-Z_a-z]|(?:[#;]|--)[\s\v]*?(?:alter|drop|(?:insert|update)[\s\v]*?[0-9A-Z_a-z]{2,})|@.+=[\s\v]*?\([\s\v]*?select|[^0-9A-Z_a-z]SET[\s\v]*?@[0-9A-Z_a-z]+"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L911
        // index 74
        Rule {
            id: 942260,
            class: "SQLI".to_string(),
            severity: "CRITICAL".to_string(),
            desc: "Detects basic SQL authentication bypass attempts 2/3".to_string(),
            re: r#"(?i)["'`][\s\v]*?(?:(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|\|\||&&)[\s\v]+[\s\v0-9A-Z_a-z]+=[\s\v]*?[0-9A-Z_a-z]+[\s\v]*?having[\s\v]+|like[^0-9A-Z_a-z]*?["'0-9`])|[0-9A-Z_a-z][\s\v]+like[\s\v]+["'`]|like[\s\v]*?["'`]%|select[\s\v]+?[\s\v"'-\),-\.0-9A-\[\]_-z]+from[\s\v]+"#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L937
        // index 75
        Rule {
            id: 942300,
            class: "SQLI".to_string(),
            severity: "CRTICIAL".to_string(),
            desc: "Detects MySQL comments, conditions and ch(a)r injections".to_string(),
            re: r#"(?i)\)[\s\v]*?when[\s\v]*?[0-9]+[\s\v]*?then|["'`][\s\v]*?(?:[#\{]|--)|/\*![\s\v]?[0-9]+|\b(?:(?:binary|cha?r)[\s\v]*?\([\s\v]*?[0-9]|(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|r(?:egexp|like))[\s\v]+[0-9A-Z_a-z]+\()|(?:\|\||&&)[\s\v]*?[0-9A-Z_a-z]+\("#.to_string(),
        },

        // https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L963
        // index 76
        Rule {
            id: 942310,
            class: "SQLI".to_string(),
            severity: "CRTIICAL".to_string(),
            desc: "Detects chained SQL injection attempts 2/2".to_string(),
            re: r#"(?i)(?:\([\s\v]*?select[\s\v]*?[0-9A-Z_a-z]+|coalesce|order[\s\v]+by[\s\v]+if[0-9A-Z_a-z]*?)[\s\v]*?\(|\*/from|\+[\s\v]*?[0-9]+[\s\v]*?\+[\s\v]*?@|[0-9A-Z_a-z]["'`][\s\v]*?(?:(?:[\+\-=@\|]+[\s\v]+?)+|[\+\-=@\|]+)[\(0-9]|@@[0-9A-Z_a-z]+[\s\v]*?[^\s\v0-9A-Z_a-z]|[^0-9A-Z_a-z]!+["'`][0-9A-Z_a-z]|["'`](?:;[\s\v]*?(?:if|while|begin)|[\s\v0-9]+=[\s\v]*?[0-9])|[\s\v\(]+case[0-9]*?[^0-9A-Z_a-z].+[tw]hen[\s\v\(]"#.to_string(),
        },

    ];
    
    rules
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn rule_sqli_942310_true() {
        let rules = rules_inbound();
        let rule = &rules[76];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"1' and 1=(select count(*) from tablenames); --\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "(select count(");
    }
    
    #[test]
    fn rule_sqli_942300_true() {
        let rules = rules_inbound();
        let rule = &rules[75];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol='{\"a\":2,\"c\":[4,5,{\"f\":7}]}' -> '$.c[2].f' = 7\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "'{");
    }
    
    #[test]
    fn rule_sqli_942260_true() {
        let rules = rules_inbound();
        let rule = &rules[74];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol = SELECT table_name FROM information_schema 1.e(tables\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "SELECT table_name FROM ");
    }
    
    #[test]
    fn rule_sqli_942210_true() {
        let rules = rules_inbound();
        let rule = &rules[73];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"|| 1==1\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "|| 1==1\"");
    }
    
    #[test]
    fn rule_sqli_942200_true() {
        let rules = rules_inbound();
        let rule = &rules[72];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"', $or: [ {}, { 'a':'a\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, ", $or: [ {}, { 'a':");
    }
    
    #[test]
    fn rule_sqli_942180_true() {
        let rules = rules_inbound();
        let rule = &rules[71];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"1' or '1'='1\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "'='");
    }
    
    #[test]
    fn rule_sqli_942150_true() {
        let rules = rules_inbound();
        let rule = &rules[70];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"';sleep(5000);\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "sleep(");
    }
    
    #[test]
    fn rule_sqli_942131_true() {
        let rules = rules_inbound();
        let rule = &rules[69];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol;}while(pt-it<5000);\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "it<5000");
    }
    
    #[test]
    fn rule_sqli_942130_true() {
        let rules = rules_inbound();
        let rule = &rules[68];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=select *! * lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, " \"lol=select");
    }
    
    #[test]
    fn rule_sqli_942120_true() {
        let rules = rules_inbound();
        let rule = &rules[67];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=' && this.password.match(/.*/)//+%00\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "&&");
    }
    
    #[test]
    fn rule_sqli_942550_true() {
        let rules = rules_inbound();
        let rule = &rules[66];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol='{\"a\":2,\"c\":[4,5,{\"f\":7}]}' -> '$.c[2].f' = 7\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "'{\"a\":2,\"c\":[4,5,{\"f\":7}]}' ->");
    }
    
    #[test]
    fn rule_sqli_942560_true() {
        let rules = rules_inbound();
        let rule = &rules[65];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol = SELECT table_name FROM information_schema 1.e(tables\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "1.e(");
    }
    
    #[test]
    fn rule_sqli_942540_true() {
        let rules = rules_inbound();
        let rule = &rules[64];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"email=admin%40juice-sh.op';&password=foo\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "{\"key\": \"email=admin%40juice-sh.op';");
    }
    
    #[test]
    fn rule_sqli_942500_true() {
        let rules = rules_inbound();
        let rule = &rules[63];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=select *! * lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "*! *");
    }
    
    #[test]
    fn rule_sqli_942360_true() {
        let rules = rules_inbound();
        let rule = &rules[62];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=alter char -- -\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "alter char ");
    }
    
    #[test]
    fn rule_sqli_942350_true() {
        let rules = rules_inbound();
        let rule = &rules[61];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=create function lol returns lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "create function lol returns");
    }
    
    #[test]
    fn rule_sqli_942320_true() {
        let rules = rules_inbound();
        let rule = &rules[60];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=create function lol () -- -\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "create function lol () -");
    }
    
    #[test]
    fn rule_nosqli_942290_true() {
        let rules = rules_inbound();
        let rule = &rules[59];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"username[$eq]=admin&password[$ne]=1 #<Equals>\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "[$eq]");
    }
    

    #[test]
    fn rule_sqli_942280_true() {
        let rules = rules_inbound();
        let rule = &rules[58];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol = select pg_sleep lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "select pg_sleep");
    }
    

    #[test]
    fn rule_sqli_942270_true() {
        let rules = rules_inbound();
        let rule = &rules[57];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol = union select from lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "union select from");
    }

    
    #[test]
    fn rule_sqli_942250_true() {
        let rules = rules_inbound();
        let rule = &rules[56];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=\"lol = merge using ( lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "merge using (");
    }

    
    #[test]
    fn rule_sqli_942240_true() {
        let rules = rules_inbound();
        let rule = &rules[55];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=\"lol=alter lol and char set lol lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "alter lol and char set lol");
    }

    
    #[test]
    fn rule_sqli_942230_true() {
        let rules = rules_inbound();
        let rule = &rules[54];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=\"lol case when lol then something\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, " case when lol then");
    }

    
    #[test]
    fn rule_sqli_942190_true() {
        let rules = rules_inbound();
        let rule = &rules[53];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=\"!lol;select \"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\"!l");
    }

    
    #[test]
    fn rule_sqli_942170_true() {
        let rules = rules_inbound();
        let rule = &rules[52];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=select benchmark ( ( lol test\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "select benchmark ( ( lol");
    }

    
    #[test]
    fn rule_sqli_942151_true() {
        let rules = rules_inbound();
        let rule = &rules[51];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=encrypt(lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "encrypt(");
    }

    
    #[test]
    fn rule_sqli_942140_true() {
        let rules = rules_inbound();
        let rule = &rules[50];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=database_name(information_schema lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "information_schema");
    }

    
    #[test]
    fn rule_template_941380_true() {
        let rules = rules_inbound();
        let rule = &rules[49];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol={{constructor.constructor('alert(1)')()}} lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "{{constructor.constructor('alert(1)')()}}");
    }

    
    #[test]
    fn rule_xss_941340_true() {
        let rules = rules_inbound();
        let rule = &rules[48];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=\"in=location.name=lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\"in=location.name=");
    }

    
    #[test]
    fn rule_xss_941330_true() {
        let rules = rules_inbound();
        let rule = &rules[47];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=\"in=location.name=lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\"in=location.name=");
    }

    
    #[test]
    fn rule_xss_941320_true() {
        let rules = rules_inbound();
        let rule = &rules[46];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=<body onload=\"alert(1)\">\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "<body ");
    }

    
    #[test]
    fn rule_xss_941150_true() {
        let rules = rules_inbound();
        let rule = &rules[45];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol style=xss\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "style=");
    }

    
    #[test]
    fn rule_xss_941120_true() {
        let rules = rules_inbound();
        let rule = &rules[44];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"<body onload=\"alert(1)\">\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, " onload=\"");
    }

    
    #[test]
    fn rule_xss_941400_true() {
        let rules = rules_inbound();
        let rule = &rules[43];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=[].sort.call`${alert}1337`\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "[].sort.call`${alert}1337`");
    }

    
    #[test]
    fn rule_xss_941390_true() {
        let rules = rules_inbound();
        let rule = &rules[42];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"test=<script>alert(\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "alert(");
    }

    
    #[test]
    fn rule_xss_941370_true() {
        let rules = rules_inbound();
        let rule = &rules[41];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"/?search=/?a=\";+alert(self[\"document\"][\"cookie\"]);\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "self[\"document\"]");
    }

    
    #[test]
    fn rule_xss_941360_true() {
        let rules = rules_inbound();
        let rule = &rules[40];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol !![] lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "!![]");
    }

    
    #[test]
    fn rule_xss_941350_true() {
        let rules = rules_inbound();
        let rule = &rules[39];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"+ADw-script+AD4-alert(+ACc-xss+ACc-)+ADw-+AC8-script+AD4-\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "+ADw-script+AD4-alert(+ACc-xss+ACc-)+ADw-+AC8-script+AD4-");
    }


    //TODO test index 38 941310
    
    
    /*
    #[test]
    fn rule_xss_941170_true() {
        let rules = rules_inbound();
        let rule = &rules[XX]; 
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"vul=<p style=\"background:url(javascript:alert(1))\">\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "(javascript:alert(");
    }
    */
    
    #[test]
    fn rule_xss_941160_true() {
        let rules = rules_inbound();
        let rule = &rules[37];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"vul=<script>alert()\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "<script");
    }

    
    #[test]
    fn rule_xss_941140_true() {
        let rules = rules_inbound();
        let rule = &rules[36];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=<p style=\"background:url(javascript:alert(1))\">\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "style=\"background:url(javascript");
    }

    
    #[test]
    fn rule_xss_941130_true() {
        let rules = rules_inbound();
        let rule = &rules[35];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol=!ENTITY | SYSTEM lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "=!ENTITY | SYSTEM");
    }

    
    #[test]
    fn rule_xss_941110_true() {
        let rules = rules_inbound();
        let rule = &rules[34];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"vul=<sCriPt>alert()\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "<sCriPt>");
    }

    
    #[test]
    fn rule_ssrf_934120_true() {
        let rules = rules_inbound();
        let rule = &rules[33];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"url=http://2852039166/\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "http://2852039166");
    }

    
    #[test]
    fn rule_deserial_934101_true() {
        let rules = rules_inbound();
        let rule = &rules[32];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"something=Process.spawn(\"id\")\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "spawn(");
    }

    
    #[test]
    fn rule_dos_934160_true() {
        let rules = rules_inbound();
        let rule = &rules[31];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol while(!false) lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "while(!false)");
    }

    
    #[test]
    fn rule_rce_934150_true() {
        let rules = rules_inbound();
        let rule = &rules[30];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"something=Process.spawn(\"id\")\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "Process.spawn(");
    }

    
    #[test]
    fn rule_pp_934130_true() {
        let rules = rules_inbound();
        let rule = &rules[29];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"something=__proto__\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "__proto__");
    }

    
    #[test]
    fn rule_deserial_934100_true() {
        let rules = rules_inbound();
        let rule = &rules[28];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol eval(ls) lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "eval(");
    }

    
    #[test]
    fn rule_rce_932331_true() {
        let rules = rules_inbound();
        let rule = &rules[27];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol !1 lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "!1");
    }

    
    #[test]
    fn rule_rce_932321_true() {
        let rules = rules_inbound();
        let rule = &rules[26];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"\r\nNOOP\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\r\nNOOP");
    }

    
    #[test]
    fn rule_rce_932311_true() {
        let rules = rules_inbound();
        let rule = &rules[25];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"\r\nlol CREATE lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\r\nlol CREATE lol\"");
    }

    
    #[test]
    fn rule_rce_932301_true() {
        let rules = rules_inbound();
        let rule = &rules[24];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"\r\nDATA 123\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\r\nDATA");
    }

    
    #[test]
    fn rule_rce_932190_true() {
        let rules = rules_inbound();
        let rule = &rules[23];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol /?*l/ lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "/?*l/");
    }

    
    #[test]
    fn rule_rce_932239_true() {
        let rules = rules_inbound();
        let rule = &rules[22];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"\r\nwh\"o \"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\r\nwh\"o");
    }

    
    #[test]
    fn rule_rce_932232_true() {
        let rules = rules_inbound();
        let rule = &rules[21];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"\r\nwh\"o \"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\r\nwh\"o");
    }

    
    #[test]
    fn rule_rce_932236_true() {
        let rules = rules_inbound();
        let rule = &rules[20];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol; unzip somefile.zip\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "; unzip ");
    }

    
    #[test]
    fn rule_rce_932320_true() {
        let rules = rules_inbound();
        let rule = &rules[19];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"\r\nlol LIST\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\r\nlol LIST");
    }

    
    #[test]
    fn rule_rce_932310_true() {
        let rules = rules_inbound();
        let rule = &rules[18];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"\r\nlol LISTRIGHTS A\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\r\nlol LISTRIGHTS A\"");
    }

    
    #[test]
    fn rule_rce_932300_true() {
        let rules = rules_inbound();
        let rule = &rules[17];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol\r\nRCPT TO:<Green@foo.com>\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "\r\nRCPT TO:<Green@foo.com>");
    }

    
    #[test]
    fn rule_rce_932210_true() {
        let rules = rules_inbound();
        let rule = &rules[16];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"username = '\";.system id\n'\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, ";.system");
    }

    
    #[test]
    fn rule_rce_932240_true() {
        let rules = rules_inbound();
        let rule = &rules[15];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol uname<() value lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "uname<() value");
    }

    
    #[test]
    fn rule_rce_932220_true() {
        let rules = rules_inbound();
        let rule = &rules[14];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"rce=whoami | ls -la\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, " | ls");
    }

    
    #[test]
    fn rule_rce_932200_true() {
        let rules = rules_inbound();
        let rule = &rules[13];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"value=/bin/bash -c 'curl \"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "/bash -c '");
    }

    
    #[test]
    fn rule_rce_932175_true() {
        let rules = rules_inbound();
        let rule = &rules[12];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"/?rce=alias a=b\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "alias a=b");
    }

    
    #[test]
    fn rule_rce_932170_true() {
        let rules = rules_inbound();
        let rule = &rules[11];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"x='() { :;};\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "() {");
    }

    
    #[test]
    fn rule_rce_932330_true() {
        let rules = rules_inbound();
        let rule = &rules[10];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"/?rce=!-1\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "!-1");
    }

    
    #[test]
    fn rule_rce_932260_true() {
        let rules = rules_inbound();
        let rule = &rules[9];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"foo=wget%20www.example.com\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "=wget");
    }

    
    #[test]
    fn rule_rce_932250_true() {
        let rules = rules_inbound();
        let rule = &rules[8];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"foo=7z \"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "=7z ");
    }

    
    #[test]
    fn rule_rce_932130_true() {
        let rules = rules_inbound();
        let rule = &rules[7];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"value $(ls -la) end\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "$(ls -la)");
    }


    #[test]
    fn rule_rce_932235_true() {
        let rules = rules_inbound();
        let rule = &rules[6];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"test=lol && whoami\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "&& whoami");
    }


    #[test]
    fn rule_rce_932230_true() {
        let rules = rules_inbound();
        let rule = &rules[5];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"some=value;ls\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, ";ls");
    }


    
    #[test]
    fn rule_rfi_931130_true() {
        let rules = rules_inbound();
        let rule = &rules[4];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"some=jar:https://lol.com/lol.zip\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "jar:https://lol.com");
    }

    
    #[test]
    fn rule_rfi_931120_true() {
        let rules = rules_inbound();
        let rule = &rules[3];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"file://lol/?\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "file://lol/?");
    }


    #[test]
    fn rule_rfi_931110_true() {
        let rules = rules_inbound();
        let rule = &rules[2];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"lol_CONF[path]=https://lol\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "_CONF[path]=https://");
    }


    #[test]
    fn rule_rfi_931100_true() {
        let rules = rules_inbound();
        let rule = &rules[1];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"file://127.0.0.1/\"}");
        let cap = search(rule, data);
        println!("Cap: {:?}", cap);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "file://127.0.0.1");
    }


    #[test]
    fn rule_lfi_930100_true() {
        let rules = rules_inbound();
        let rule = &rules[0];
        let data: Bytes =  Bytes::from_static(b"{\"key\": \"not/a/..././..././vuln\"}");
        let cap = search(rule, data);
        
        assert!(!cap.is_empty());
        assert_eq!(cap, "/.../");
    }
    

    #[test]
    fn rule_all_false() {
        let rules = rules_inbound();
        let rule_count = rules.iter().count();
        for i in 0..rule_count {
            let rule = &rules[i];
            let data: Bytes =  Bytes::from_static(b"{\"key\": \"include //lol/\"}");
            let cap = search(rule, data);
            println!("Cap: {:?}", cap);
        
            assert!(cap.is_empty());
            assert_eq!(cap, "");
        }
    }


    #[test]
    fn rules_test() {
        rules_inbound();
    }


    fn search(rule: &Rule, data: Bytes) -> String {
        let needle = str::from_utf8(&data).unwrap();
        //println!("Needle: {:?}", needle);
        let expression = rule.re.as_str();
        //println!("Expression: {:?}", expression);
        let re = Regex::new(format!(r"{}", expression).as_str()).unwrap();
        let Some(caps) = re.captures(needle) else {
            return "".to_string()
        };
        let cap: &str = &caps[0];
        
        cap.to_string()
    }
}



