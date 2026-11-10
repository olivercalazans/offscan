/*
 * Copyright (C) 2025 Oliver R. Calazans Jeronimo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org>.
 */


use std::collections::HashMap;


pub fn align4(n: usize) -> usize {
    (n + 3) & !3
}



pub fn genl_hdr(cmd: u8, version: u8) -> Vec<u8> {
    vec![cmd, version, 0, 0]
}



pub fn put_attr(mut buf: Vec<u8>, typ: u16, data: &[u8]) -> Vec<u8> {
    let length = 4 + data.len();
    let aligned = align4(length);
    let mut attr = vec![0u8; aligned];
    attr[0..2].copy_from_slice(&(length as u16).to_le_bytes());
    attr[2..4].copy_from_slice(&typ.to_le_bytes());
    attr[4..4 + data.len()].copy_from_slice(data);
    buf.extend_from_slice(&attr);
    buf
}



pub fn put_u32_attr(buf: Vec<u8>, typ: u16, v: u32) -> Vec<u8> {
    put_attr(buf, typ, &v.to_le_bytes())
}



pub fn put_string_attr(buf: Vec<u8>, typ: u16, s: &str) -> Vec<u8> {
    let mut data = s.as_bytes().to_vec();
    data.push(0);
    put_attr(buf, typ, &data)
}



pub fn parse_attrs(buf: &[u8]) -> HashMap<u16, Vec<u8>> {
    let mut out = HashMap::new();
    let mut buf = buf;
    while buf.len() >= 4 {
        let alen = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let atyp = u16::from_le_bytes([buf[2], buf[3]]);
        if alen < 4 || alen > buf.len() {
            break;
        }
        out.insert(atyp & 0x3fff, buf[4..alen].to_vec());
        let next = align4(alen);
        if next > buf.len() {
            break;
        }
        buf = &buf[next..];
    }
    out
}