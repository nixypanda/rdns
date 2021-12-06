// Ignore: util function to intersperse delimiter to a vector of strings
// Extra hacky
pub fn isperse(input: Vec<String>) -> String {
    let string = input
        .into_iter()
        .fold("".to_string(), |acc, x| format!("{}.{}", acc, x));

    let mut chars = string.chars();
    chars.next();
    chars.as_str().to_string()
}
