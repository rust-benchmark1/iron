use serde_yaml::Value;

pub fn deserialize_yaml_string(user_input: String) {
    //SINK
    let _user: Value = serde_yaml::from_str(&user_input).expect("YAML deserialization failed");
}
