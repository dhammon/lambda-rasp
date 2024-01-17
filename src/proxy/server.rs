use crate::proxy::inspect::security_check;
use std::{
    str::FromStr,
    result::Result,
    error::Error,
    convert::Infallible,
    net::SocketAddr
};
use hyper::{
    {Body, body, Request, Response, Client, Uri, Server, Method},
    service::{make_service_fn, service_fn},
    header::{HeaderValue, HOST},
};
#[cfg(test)]
use hyper::body::Bytes;


const RAPID_HOST: &str = "127.0.0.1:9001";


pub async fn start_api_svr(port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(rapid_proxy))
    });
    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("[-] Server error: {}", e);
    }
}


async fn send_req(mut req: Request<Body>) -> Result<Response<Body>, Box<dyn Error>> {
    req.headers_mut().insert(HOST, HeaderValue::from_static(RAPID_HOST));
    let req_uri = format!("http://{}{}", RAPID_HOST, req.uri().path());
    *req.uri_mut() = Uri::from_str(req_uri.as_str()).unwrap();
    let client = Client::new();
    let resp = client.request(req).await?;

    Ok(resp)
}

#[tokio::test]
//requires http server: python3 -m http.server 9001
async fn send_req_test() {
    let data = Bytes::from_static(b"lol");
    let payload = Body::from(data);
    let mock_req: Request<Body> = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:9002")
        .body(payload)
        .unwrap();
    let _response = send_req(mock_req).await.unwrap();
}


async fn hook_next(req: Request<Body>) -> Result<Response<Body>, Box<dyn Error>> {
    let (parts, body) = send_req(req).await.unwrap().into_parts();
    let data = body::to_bytes(body).await.unwrap();

    if crate::VERBOSE {
        println!("[+] Captured Invoke Headers: {:#?}", parts.headers);
        println!("[+] Captured Invoke Data: {:?}", data);
    }
    security_check(&data); 
    let resp = Response::from_parts(parts, Body::from(data));

    Ok(resp)
}


#[tokio::test]
async fn hook_next_test() {
    let data = Bytes::from_static(b"{\"lol\": \"value\"}");
    let payload = Body::from(data);
    let mock_req: Request<Body> = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:9002")
        .body(payload)
        .unwrap();
    let _response = hook_next(mock_req).await.unwrap();
}


async fn hook_response(req: Request<Body>) -> Result<Response<Body>, Box<dyn Error>> {
    let (parts, body) = req.into_parts();
    let hdr = parts.headers.clone();
    let data = body::to_bytes(body).await.unwrap();

    //TODO inspect response value

    if crate::VERBOSE {
        println!("[+] Captured Resp Headers: {:?}", hdr);
        println!("[+] Captured Resp Event: {:?}", data);
    }

    let newreq = Request::from_parts(parts, Body::from(data));
    let resp = send_req(newreq).await.unwrap();
    
    Ok(resp)
}


#[tokio::test]
async fn hook_response_test() {
    let data = Bytes::from_static(b"{\"lol\": \"value\"}");
    let payload = Body::from(data);
    let mock_req: Request<Body> = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:9002")
        .body(payload)
        .unwrap();
    let _response = hook_response(mock_req).await.unwrap();
}


async fn rapid_proxy(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path();
    
    match req.method() {
        &Method::GET => {
            if path.starts_with("/2018-06-01/runtime/invocation/next") {
                let resp = hook_next(req).await.unwrap();
                return Ok(resp);
            }
        }
        &Method::POST => {
            // Runtime is sending us a completion response
            if path.starts_with("/2018-06-01/runtime/invocation/") && path.ends_with("/response") {
                let resp = hook_response(req).await.unwrap();
                return Ok(resp);
            }
        }
        _default => {}
    };
    
    let resp = send_req(req).await.unwrap();
    
    Ok(resp)
}


#[tokio::test]
async fn rapid_proxy_test_next() {
    let data = Bytes::from_static(b"{\"lol\": \"value\"}");
    let payload = Body::from(data);
    let mock_req: Request<Body> = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:9002/2018-06-01/runtime/invocation/next")
        .body(payload)
        .unwrap();
    let response = rapid_proxy(mock_req).await.unwrap();
    assert_eq!(response.status(), 404);
}


#[tokio::test]
async fn rapid_proxy_test_response() {
    let data = Bytes::from_static(b"{\"lol\": \"value\"}");
    let payload = Body::from(data);
    let mock_req: Request<Body> = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:9002/2018-06-01/runtime/invocation/123abc/response")
        .body(payload)
        .unwrap();
    let response = rapid_proxy(mock_req).await.unwrap();
    assert_eq!(response.status(), 501);
}








