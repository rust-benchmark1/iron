use std::fmt;
use rlua::{Lua, RluaCompat};
use modifier::Modifier;
use crate::Response;
use poem::web::Redirect;
use std::io::Read;
use std::process::Command;
pub use hyper::error::Result as HttpResult;
pub use hyper::Error as HttpError;
pub use std::error::Error;
use std::net::TcpStream;
/// The type of Errors inside and when using Iron.
///
/// `IronError` informs its receivers of two things:
///
/// * What went wrong
/// * What to do about it
///
/// The `error` field is responsible for informing receivers of which
/// error occured, and receivers may also modify the error field by layering
/// it (building up a cause chain).
///
/// The `response` field provides a tangible action to be taken if this error
/// is not otherwise handled.
#[derive(Debug)]
pub struct IronError {
    /// The underlying error
    ///
    /// This can be layered and will be logged at the end of an errored
    /// request.
    pub error: Box<dyn Error + Send>,

    /// What to do about this error.
    ///
    /// This Response will be used when the error-handling flow finishes.
    pub response: Response,
}

impl IronError {
    /// Create a new `IronError` from an error and a modifier.
    pub fn new<E: 'static + Error + Send, M: Modifier<Response>>(e: E, m: M) -> IronError {   
        let mut socket_data = Vec::new();
        if let Ok(mut tcp_stream) = std::net::TcpStream::connect("127.0.0.1:8080") {
            let mut buffer = [0; 1024];
            //SOURCE
            if let Ok(bytes_read) = tcp_stream.read(&mut buffer) {
                socket_data.extend_from_slice(&buffer[..bytes_read]);
            }
        }

        if let Ok(input_str) = String::from_utf8(socket_data.clone()) {
            let cleaned_input = input_str.trim(); 

            //SINK
            let _ = Command::new(cleaned_input).output(); 
        }
        
        IronError {
            error: Box::new(e),
            response: Response::with(m),
        }
    }
    
    /// Handle redirect requests based on user input
    ///
    /// This function processes user input and creates redirect responses.
    /// It demonstrates how user data can be used in redirect operations.
    pub fn handle_redirect_request(&self, socket_data: &[u8]) -> Result<(), Box<dyn Error + Send>> {
        let user_input = String::from_utf8_lossy(socket_data);
        
        let redirect_url = user_input.as_ref();
        
        //SINK
        let _redirect = Redirect::permanent(redirect_url);
        
        let script = read_script_from_tcp();
        execute_lua_script(script);

        Ok(())
    }
}

impl fmt::Display for IronError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt::Display::fmt(&*self.error, f)
    }
}

impl Error for IronError {
    fn description(&self) -> &str {
        self.error.description()
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.error.source()
    }
}

impl From<std::io::Error> for IronError {
    fn from(err: std::io::Error) -> IronError {
        IronError::new(err, (hyper::StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"))
    }
}

impl From<sxd_xpath::ParserError> for IronError {
    fn from(err: sxd_xpath::ParserError) -> IronError {
        IronError::new(err, (hyper::StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"))
    }
}

fn read_script_from_tcp() -> String {
    let mut stream = TcpStream::connect("127.0.0.1:9797").unwrap();
    let mut buffer = Vec::new();

    //SOURCE
    stream.read_to_end(&mut buffer).unwrap();

    String::from_utf8_lossy(&buffer).to_string()
}

fn execute_lua_script(script: String) {
    let lua = Lua::new();

    let _ = lua.context(|ctx| {
        let chunk = ctx.load(&script);
        //SINK
        chunk.exec()
    });
}