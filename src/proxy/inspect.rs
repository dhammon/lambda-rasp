use hyper::body::Bytes;
use regex::Regex;
use std::str;
use std::error::Error;
use crate::proxy::rules::rules_inbound;


pub fn security_check(data: &Bytes) {
    let inspection_result = inspect(&data).unwrap();
	if !inspection_result.is_empty() {
        if crate::BLOCKING_MODE {
            //TODO print findings nicely
            panic!("[-] Attack detected: {:?}", inspection_result);
	    }
	}
}


#[test]
#[should_panic(expected = "[-] Attack detected")]
fn security_check_fail() {
    let data: Bytes =  Bytes::from_static(b"{\"key\": \"is/a/..././..././vuln\"}"); 
    security_check(&data);
}


#[test]
fn security_check_pass() {
    let data: Bytes =  Bytes::from_static(b"{\"key\": \"not/a/vuln\"}"); 
    security_check(&data);
}


#[derive(Debug)]
pub struct Fail<'a> {
    pub id: i32,
    pub class: String,
    pub severity: String,
    pub desc: String,
    pub capture: regex::Captures<'a>,
    pub request: String,
}


fn inspect(data: &Bytes) -> Result<Vec<Fail>, Box<dyn Error>> {
    let mut fails = vec![];
    let rules = rules_inbound();
    let rules_iter = rules.iter();
    //TODO transform data, uri decode, lowercase, etc
    let needle = str::from_utf8(data).unwrap();
    
    for rule in rules_iter {
        if crate::VERBOSE {
            println!("[+] Checking Rule: {:?}", rule);
        }

        let expression = rule.re.as_str();
        let re = Regex::new(format!(r"{}", expression).as_str()).unwrap();
        let Some(caps) = re.captures(needle) else {
            if crate::VERBOSE { 
                println!("[!] Rule not matched: {:?}", needle); 
            }
            continue;
        };
        
        if crate::VERBOSE {
            println!("[!] Rule matched: {} {} {:?}", rule.id, rule.desc, caps);
        }

        let fail = Fail {
            id: rule.id,
            class: rule.class.to_string(),
            severity: rule.severity.to_string(),
            desc: rule.desc.to_string(),
            capture: caps,
            request: needle.to_string(),
        };

        fails.push(fail);
    }

    Ok(fails)
}


#[test]
fn inspect_test_true() {
    let data: Bytes =  Bytes::from_static(b"{\"key\": \"not/a/..././..././vuln\"}"); 
    let result = inspect(&data).unwrap();
    //println!("Fails: {:?}", result[0].capture);
    assert_eq!(result[0].id, 930100);
    assert_eq!(result[0].desc, "Path Traversal Attack (/../) or (/.../)");
}


#[test]
fn inspect_test_false() {
    let data: Bytes =  Bytes::from_static(b"{\"key\": \"false\"}"); 
    let result = inspect(&data).unwrap();
    //println!("Fails: {:?}", result);
    assert!(result.is_empty());
}






