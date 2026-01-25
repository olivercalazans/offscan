pub(crate) fn parse_channel(channel: &str) -> Result<i32, String> {
    let channel_num: i32 = channel.parse()
        .map_err(|_| format!("'{}' is an invalid number", channel))?;
    
    if channel_num < 1 || channel_num > 165 {
        return Err(format!("The channel must be between 1 and 165 (input: {})", channel_num));
    }

    Ok(channel_num)
}