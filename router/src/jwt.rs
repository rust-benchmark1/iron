use jsonwebtoken::decode_header;

pub fn process_token(token: String) -> String {
    //SINK
    let header = decode_header(&token);

    format!("Header: {:?}", header)
}
