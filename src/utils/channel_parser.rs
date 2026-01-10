pub(crate) fn parse_channel(channel: &str) -> Result<i32, String> {
    // Tenta converter a string para i32
    let channel_num: i32 = channel.parse()
        .map_err(|_| format!("'{}' não é um número válido", channel))?;
    
    // Agora faz a validação
    if channel_num < 1 || channel_num > 165 {
        return Err(format!("O canal deve estar entre 1 e 165 (recebido: {})", channel_num));
    }

    Ok(channel_num)
}