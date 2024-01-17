mod proxy;

use proxy::memory::{patch_rapid};
use proxy::server::{start_api_svr};
use lambda_extension::{service_fn, Error, LambdaEvent, NextEvent};

const VERBOSE: bool = true;
const FAIL_OPEN: bool = false;
const BLOCKING_MODE: bool = true;

async fn ls_ext(event: LambdaEvent) -> Result<(), Error> {
    match event.next {
        NextEvent::Shutdown(_e) => {
            // TODO: Cleanly exit on shutdown event
        }
        NextEvent::Invoke(_e) => {
        }
    }
    Ok(())
}


#[tokio::main]
async fn main() -> Result<(), Error> {
    //TODO proxy switch
    //TODO don't unwrap, use error handling
    patch_rapid().unwrap();

    // Start the proxy server used to capture all event activity within
    // the Lambda environment
    tokio::spawn(async move {
        start_api_svr(8888).await;
    });

	
    // Start the Lambda service boilerplate code
    let func = service_fn(ls_ext);
    lambda_extension::run(func).await
}


